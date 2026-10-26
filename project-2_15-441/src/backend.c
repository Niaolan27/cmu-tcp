/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the TCP in the Wild course project developed for the
 * Computer Networks course (15-441/641) taught at Carnegie Mellon University.
 *
 * No part of the project may be copied and/or distributed without the express
 * permission of the 15-441/641 course staff.
 *
 *
 * This file implements the CMU-TCP backend. The backend runs in a different
 * thread and handles all the socket operations separately from the application.
 *
 * This is where most of your code should go. Feel free to modify any function
 * in this file.
 */

#include "backend.h"

#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include "cmu_packet.h"
#include "cmu_tcp.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))

// Backend loop heartbeat: how long each iteration waits for a packet (ms).
#define LOOP_TICK_MS 20

/**
 * Milliseconds elapsed since `then`, measured on the monotonic clock.
 */
static long ms_since(const struct timespec *then) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - then->tv_sec) * 1000L +
         (now.tv_nsec - then->tv_nsec) / 1000000L;
}

/**
 * Picks a random initial sequence number from the kernel's entropy pool.
 * rand() seeded with time and PID repeats across runs started close together
 * (same second, or a fresh container reusing the same PID). Falls back to
 * rand() if /dev/urandom can't be read.
 */
static uint32_t random_isn(void) {
  uint32_t isn;
  FILE *urandom = fopen("/dev/urandom", "rb");
  if (urandom != NULL) {
    size_t n = fread(&isn, sizeof(isn), 1, urandom);
    fclose(urandom);
    if (n == 1) {
      return isn;
    }
  }
  return (uint32_t)rand();
}

/**
 * Free space in the receive buffer, which is what we advertise. Out-of-order
 * segments aren't subtracted: `handle_data` only accepts bytes below the
 * window's right edge, which keeps them within this space too. Caller holds
 * recv_lock, since cmu_read shrinks `received_len`.
 */
static uint16_t advertised_window(cmu_socket_t *sock) {
  return MAX_NETWORK_BUFFER - sock->received_len;
}

/**
 * Sends a header-only packet (no payload) to the socket's peer.
 *
 * @param sock The socket to send on.
 * @param seq Sequence number to put in the header.
 * @param ack Acknowledgement number to put in the header.
 * @param flags Header flags (e.g. SYN_FLAG_MASK).
 */
static void send_empty_packet(cmu_socket_t *sock, uint32_t seq, uint32_t ack,
                              uint8_t flags) {
  socklen_t conn_len = sizeof(sock->conn);
  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen;
  uint16_t adv_window = advertised_window(sock);
  uint8_t *pkt = create_packet(src, dst, seq, ack, hlen, plen, flags,
                               adv_window, 0, NULL, NULL, 0);

  sendto(sock->socket, pkt, plen, 0, (struct sockaddr *)&(sock->conn),
         conn_len);
  sock->sent_zero_window = adv_window == 0;
  free(pkt);
}

/**
 * Sends one data packet to the socket's peer.
 *
 * @param sock The socket to send on.
 * @param seq Sequence number of the first payload byte.
 * @param payload The bytes to send.
 * @param payload_len Number of bytes to send; at most MSS.
 */
static void send_data_segment(cmu_socket_t *sock, uint32_t seq,
                              uint8_t *payload, uint16_t payload_len) {
  socklen_t conn_len = sizeof(sock->conn);
  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint32_t ack = sock->window.next_seq_expected;
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen + payload_len;
  uint8_t flags = ACK_FLAG_MASK;  // Every packet after the SYN carries an ACK.
  uint16_t adv_window = advertised_window(sock);
  uint8_t *pkt = create_packet(src, dst, seq, ack, hlen, plen, flags,
                               adv_window, 0, NULL, payload, payload_len);

  sendto(sock->socket, pkt, plen, 0, (struct sockaddr *)&(sock->conn),
         conn_len);
  sock->sent_zero_window = adv_window == 0;
  free(pkt);
}

/**
 * Bytes sent but not yet acknowledged.
 */
static uint32_t bytes_in_flight(cmu_socket_t *sock) {
  return sock->window.next_seq_to_send - sock->window.last_ack_received;
}

/**
 * A SYN-ACK is valid if it acknowledges our ISN.
 */
static int check_valid_syn_ack(cmu_socket_t *sock, cmu_tcp_header_t *hdr) {
  return get_ack(hdr) == sock->isn + 1;
}

/**
 * A third-leg ACK is valid if it acknowledges our SYN-ACK.
 */
static int check_valid_ack(cmu_socket_t *sock, cmu_tcp_header_t *hdr) {
  return get_ack(hdr) == sock->window.last_ack_received + 1;
}

/**
 * Tells if a given sequence number has been acknowledged by the socket.
 *
 * @param sock The socket to check for acknowledgements.
 * @param seq Sequence number to check.
 *
 * @return 1 if the sequence number has been acknowledged, 0 otherwise.
 */
int has_been_acked(cmu_socket_t *sock, uint32_t seq) {
  int result;
  result = after(sock->window.last_ack_received, seq);
  return result;
}

/**
 * Resends the oldest unacknowledged bytes, at most `max_len` of them, and
 * restarts the retransmit timer. Leaves `next_seq_to_send` alone.
 *
 * @param sock The socket to use for sending data.
 * @param max_len Most bytes to resend: MSS for a lost segment, 1 for a probe.
 */
static void retransmit_oldest(cmu_socket_t *sock, uint32_t max_len) {
  uint16_t payload_len = MIN(max_len, bytes_in_flight(sock));
  send_data_segment(sock, sock->window.last_ack_received, sock->outbound_buf,
                    payload_len);
  clock_gettime(CLOCK_MONOTONIC, &sock->sent_data_time);
}

/**
 * Three duplicate ACKs: halve the window, inflate it by the three segments
 * that left the network, and fast-retransmit the missing segment.
 */
static void enter_fast_recovery(cmu_socket_t *sock) {
  sock->ssthresh = MAX(sock->cwnd / 2, 2 * MSS);
  sock->cwnd = sock->ssthresh + 3 * MSS;
  sock->cc_state = FAST_RECOVERY;
  retransmit_oldest(sock, MSS);
}

/**
 * Retransmit timeout: halve ssthresh, collapse the window to one segment, and
 * resend only the missing segment. The receiver buffers what came after it.
 */
static void enter_slow_start(cmu_socket_t *sock) {
  sock->ssthresh = MAX(sock->cwnd / 2, 2 * MSS);
  sock->cwnd = WINDOW_INITIAL_WINDOW_SIZE;
  sock->dup_ack_count = 0;
  sock->cc_state = SLOW_START;
  retransmit_oldest(sock, MSS);
}

/**
 * Grows or deflates the congestion window for an ACK that advanced the base.
 *
 * @param sock The socket whose congestion window to update.
 * @param acked Bytes the ACK newly acknowledged.
 */
static void on_new_ack(cmu_socket_t *sock, uint32_t acked) {
  switch (sock->cc_state) {
    case SLOW_START:
      sock->cwnd += MSS;
      if (sock->cwnd >= sock->ssthresh) {
        sock->cc_state = CONGESTION_AVOIDANCE;
      }
      break;
    case CONGESTION_AVOIDANCE:
      // MSS*MSS/cwnd per MSS acknowledged, so a window's worth of data adds
      // about one MSS however it was segmented. The floor keeps ACKs for tiny
      // segments from rounding down to nothing.
      sock->cwnd += MAX(1, (MSS * MSS / sock->cwnd) * acked / MSS);
      break;
    case FAST_RECOVERY:
      sock->cwnd = sock->ssthresh;
      sock->cc_state = CONGESTION_AVOIDANCE;
      break;
  }
  sock->dup_ack_count = 0;
}

/**
 * Counts a duplicate ACK; the third one triggers fast retransmit. In fast
 * recovery each one means another segment left the network.
 */
static void on_dup_ack(cmu_socket_t *sock) {
  if (sock->cc_state == FAST_RECOVERY) {
    sock->cwnd += MSS;
    return;
  }
  sock->dup_ack_count++;
  if (sock->dup_ack_count == 3) {
    enter_fast_recovery(sock);
  }
}

/**
 * Handles an acknowledgement received after the handshake. A new ACK slides
 * the send window; a duplicate one feeds congestion control. ACKs for bytes
 * never sent (ack > next_seq_to_send) and older ACKs are ignored.
 *
 * @param sock The socket whose window to slide.
 * @param ack The acknowledgement number received.
 * @param is_pure_ack Whether the packet carried no payload.
 */
static void handle_ack(cmu_socket_t *sock, uint32_t ack, int is_pure_ack) {
  if (ack == sock->window.last_ack_received) {
    // With a zero window, repeated ACKs answer our probes; they aren't loss.
    if (is_pure_ack && bytes_in_flight(sock) > 0 && sock->rwnd > 0) {
      on_dup_ack(sock);
    }
    return;
  }
  if (!after(ack, sock->window.last_ack_received) ||
      after(ack, sock->window.next_seq_to_send)) {
    return;
  }
  uint32_t acked = ack - sock->window.last_ack_received;
  sock->outbound_len -= acked;
  memmove(sock->outbound_buf, sock->outbound_buf + acked, sock->outbound_len);
  sock->window.last_ack_received = ack;
  // Restart so the timer covers the new oldest segment.
  if (bytes_in_flight(sock) > 0) {
    clock_gettime(CLOCK_MONOTONIC, &sock->sent_data_time);
  }
  on_new_ack(sock, acked);
}

/**
 * Appends in-order bytes to `received_buf` for cmu_read.
 */
static void deliver(cmu_socket_t *sock, uint8_t *data, uint32_t len) {
  sock->received_buf = realloc(sock->received_buf, sock->received_len + len);
  memcpy(sock->received_buf + sock->received_len, data, len);
  sock->received_len += len;
  sock->window.next_seq_expected += len;
}

/**
 * Stores a segment that arrived beyond a gap, keeping the list sorted by seq.
 * A segment already buffered at the same seq is a duplicate and is dropped.
 */
static void buffer_ooo(cmu_socket_t *sock, uint32_t seq, uint8_t *data,
                       uint16_t len) {
  ooo_segment_t **link = &sock->ooo_head;
  while (*link != NULL && before((*link)->seq, seq)) {
    link = &(*link)->next;
  }
  if (*link != NULL && (*link)->seq == seq) {
    return;
  }
  ooo_segment_t *segment = malloc(sizeof(ooo_segment_t));
  segment->seq = seq;
  segment->len = len;
  segment->data = malloc(len);
  memcpy(segment->data, data, len);
  segment->next = *link;
  *link = segment;
}

/**
 * Delivers buffered segments that the last delivery made contiguous, trimming
 * any bytes already delivered, and frees them.
 */
static void drain_ooo(cmu_socket_t *sock) {
  while (sock->ooo_head != NULL &&
         !after(sock->ooo_head->seq, sock->window.next_seq_expected)) {
    ooo_segment_t *segment = sock->ooo_head;
    uint32_t end = segment->seq + segment->len;
    if (after(end, sock->window.next_seq_expected)) {
      uint32_t skip = sock->window.next_seq_expected - segment->seq;
      deliver(sock, segment->data + skip, segment->len - skip);
    }
    sock->ooo_head = segment->next;
    free(segment->data);
    free(segment);
  }
}

/**
 * Accepts a data packet's payload if it fits in the advertised window:
 * in-order bytes go to `received_buf` (along with any buffered segments they
 * make contiguous), bytes beyond a gap go to the out-of-order buffer. Answers
 * every data packet, accepted or not, with a cumulative acknowledgement, so a
 * sender whose ACK was lost learns what already arrived.
 *
 * @param sock The socket receiving the data.
 * @param pkt The data packet.
 */
static void handle_data(cmu_socket_t *sock, uint8_t *pkt) {
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  uint32_t seq = get_seq(hdr);
  uint16_t payload_len = get_payload_len(pkt);
  uint8_t *payload = get_payload(pkt);
  uint32_t expected = sock->window.next_seq_expected;
  uint32_t end = seq + payload_len;
  uint32_t right_edge = expected + advertised_window(sock);

  // Skip segments already delivered (end <= expected) or not fully inside the
  // window. A zero-window probe lands here and only earns an ACK.
  if (after(end, expected) && !after(end, right_edge)) {
    if (!after(seq, expected)) {
      // Resegmented retransmissions can overlap delivered bytes; skip them.
      uint32_t skip = expected - seq;
      deliver(sock, payload + skip, payload_len - skip);
      drain_ooo(sock);
    } else {
      buffer_ooo(sock, seq, payload, payload_len);
    }
  }

  // Cumulative ACK: everything before next_seq_expected, whatever arrived.
  send_empty_packet(sock, sock->window.last_ack_received,
                    sock->window.next_seq_expected, ACK_FLAG_MASK);
}

/**
 * Updates the socket information to represent the newly received packet.
 *
 * ACKs slide the send window. Data packets (which carry the ACK flag) are
 * answered with a cumulative acknowledgement; pure ACKs are never answered.
 *
 * @param sock The socket used for handling packets received.
 * @param pkt The packet data received by the socket.
 */
void handle_message(cmu_socket_t *sock, uint8_t *pkt) {
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  uint8_t flags = get_flags(hdr);

  // Every packet carries the peer's free receive space.
  sock->rwnd = get_advertised_window(hdr);

  switch (flags) {
    case SYN_FLAG_MASK: {
      if (sock->handshake_state == INIT) {
        sock->isn = random_isn();
        sock->window.last_ack_received = sock->isn;
        sock->window.next_seq_expected = get_seq(hdr) + 1;
        send_empty_packet(sock, sock->window.last_ack_received,
                          sock->window.next_seq_expected,
                          SYN_FLAG_MASK | ACK_FLAG_MASK);
        clock_gettime(CLOCK_MONOTONIC, &sock->sent_synack_time);
        sock->handshake_state = RECEIVED_SYN;
      }
      // Otherwise drop it.
      break;
    }
    case (SYN_FLAG_MASK | ACK_FLAG_MASK): {
      if (sock->handshake_state == SENT_SYN && check_valid_syn_ack(sock, hdr)) {
        sock->window.next_seq_expected = get_seq(hdr) + 1;
        sock->window.last_ack_received = get_ack(hdr);
        sock->window.next_seq_to_send = sock->window.last_ack_received;
        send_empty_packet(sock, sock->window.last_ack_received,
                          sock->window.next_seq_expected, ACK_FLAG_MASK);
        sock->handshake_state = HANDSHAKE_ESTABLISHED;
      } else if (sock->handshake_state == HANDSHAKE_ESTABLISHED &&
                 check_valid_syn_ack(sock, hdr)) {
        // Duplicate SYN-ACK: our ACK was likely lost, so re-ACK.
        send_empty_packet(sock, sock->window.last_ack_received,
                          sock->window.next_seq_expected, ACK_FLAG_MASK);
      }
      // Otherwise drop it.
      break;
    }
    case ACK_FLAG_MASK: {
      uint32_t ack = get_ack(hdr);
      if (sock->handshake_state == RECEIVED_SYN) {
        // The third-leg ACK, or a data packet carrying it if that ACK was
        // lost. It covers our SYN-ACK's seq, which was never in outbound_buf,
        // so it moves base without trimming.
        if (!check_valid_ack(sock, hdr)) {
          break;
        }
        sock->window.last_ack_received = ack;
        sock->window.next_seq_to_send = ack;
        sock->handshake_state = HANDSHAKE_ESTABLISHED;
      } else if (sock->handshake_state == HANDSHAKE_ESTABLISHED) {
        handle_ack(sock, ack, get_payload_len(pkt) == 0);
      } else {
        // Before the handshake, next_seq_to_send isn't set yet, so the
        // window's range check would be meaningless.
        break;
      }
      // Data packets carry the ACK flag; pure ACKs have no payload.
      if (get_payload_len(pkt) > 0) {
        handle_data(sock, pkt);
      }
      break;
    }
    default: {
      // Data without the ACK flag. Ignore it until the handshake is
      // established.
      if (sock->handshake_state == HANDSHAKE_ESTABLISHED) {
        handle_data(sock, pkt);
      }
    }
  }
}

/**
 * Checks if the socket received any data.
 *
 * It first peeks at the header to figure out the length of the packet and then
 * reads the entire packet.
 *
 * @param sock The socket used for receiving data on the connection.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information.
 * @param timeout_ms How long to wait in `TIMEOUT` mode; ignored otherwise.
 */
void check_for_data(cmu_socket_t *sock, cmu_read_mode_t flags,
                    int timeout_ms) {
  cmu_tcp_header_t hdr;
  uint8_t *pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;

  // No lock while waiting: only the backend thread reads the socket, and
  // holding recv_lock across poll() starves cmu_read on the app thread.
  switch (flags) {
    case NO_FLAG:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), MSG_PEEK,
                     (struct sockaddr *)&(sock->conn), &conn_len);
      break;
    case TIMEOUT: {
      // Using `poll` here so that we can specify a timeout.
      struct pollfd ack_fd;
      ack_fd.fd = sock->socket;
      ack_fd.events = POLLIN;
      // Timeout after timeout_ms.
      if (poll(&ack_fd, 1, timeout_ms) <= 0) {
        break;
      }
    }
    // Fallthrough.
    case NO_WAIT:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t),
                     MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),
                     &conn_len);
      break;
    default:
      perror("ERROR unknown flag");
  }
  if (len >= (ssize_t)sizeof(cmu_tcp_header_t)) {
    plen = get_plen(&hdr);
    pkt = malloc(plen);
    while (buf_size < plen) {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                   (struct sockaddr *)&(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    // handle_message appends to received_buf, which cmu_read shares.
    while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
    }
    handle_message(sock, pkt);
    pthread_mutex_unlock(&(sock->recv_lock));
    free(pkt);
  }
}

/**
 * Sends as much unsent data from `outbound_buf` as the window allows. Never
 * blocks: ACKs slide the window in `handle_message`, and the backend loop calls
 * this again on its next iteration to fill the space they free.
 *
 * The window is min(cwnd, rwnd). If the peer's window is closed and nothing is
 * in flight, sends a 1-byte zero-window probe instead; the retransmit timer
 * then re-probes every DEFAULT_TIMEOUT until an ACK reopens the window.
 *
 * @param sock The socket to use for sending data.
 */
void single_send(cmu_socket_t *sock) {
  uint32_t window = MIN(sock->cwnd, sock->rwnd);
  uint32_t outbound_len = sock->outbound_len;
  uint32_t in_flight = bytes_in_flight(sock);

  if (window == 0 && in_flight == 0) {
    window = 1;
  }
  while (in_flight < window && in_flight < outbound_len) {
    uint16_t payload_len =
        MIN(MIN((uint32_t)MSS, outbound_len - in_flight), window - in_flight);
    // Sending into an empty pipe: start the retransmit timer.
    if (in_flight == 0) {
      clock_gettime(CLOCK_MONOTONIC, &sock->sent_data_time);
    }
    send_data_segment(sock, sock->window.next_seq_to_send,
                      sock->outbound_buf + in_flight, payload_len);
    sock->window.next_seq_to_send += payload_len;
    in_flight += payload_len;
  }
}

/**
 * Opens the congestion-control trace if CWND_LOG names a file. Rows are
 * line-buffered so the trace survives the process being killed mid-transfer.
 */
static void cc_log_open(cmu_socket_t *sock) {
  const char *path = getenv("CWND_LOG");
  cc_log_t *trace = &sock->cc_log;

  trace->file = NULL;
  if (path == NULL) {
    return;
  }
  trace->file = fopen(path, "w");
  if (trace->file == NULL) {
    perror("ERROR opening CWND_LOG");
    return;
  }
  setvbuf(trace->file, NULL, _IOLBF, 0);
  fprintf(trace->file, "time_s,cwnd,ssthresh,state,rwnd\n");
  clock_gettime(CLOCK_MONOTONIC, &trace->start);
  trace->cwnd = 0;  // Never a real cwnd, so the first row always gets written.
}

/**
 * Appends a row to the congestion-control trace if cwnd, ssthresh, or the
 * congestion state changed since the last row. Time is seconds since the
 * backend started; rwnd is the peer's last advertised window.
 */
static void cc_log_write(cmu_socket_t *sock) {
  static const char *state_names[] = {"SLOW_START", "CONGESTION_AVOIDANCE",
                                      "FAST_RECOVERY"};
  cc_log_t *trace = &sock->cc_log;
  struct timespec now;

  if (trace->file == NULL || sock->handshake_state != HANDSHAKE_ESTABLISHED) {
    return;
  }
  if (trace->cwnd == sock->cwnd && trace->ssthresh == sock->ssthresh &&
      trace->cc_state == sock->cc_state) {
    return;
  }
  clock_gettime(CLOCK_MONOTONIC, &now);
  fprintf(trace->file, "%.6f,%u,%u,%s,%u\n",
          (now.tv_sec - trace->start.tv_sec) +
              (now.tv_nsec - trace->start.tv_nsec) / 1e9,
          sock->cwnd, sock->ssthresh, state_names[sock->cc_state], sock->rwnd);
  trace->cwnd = sock->cwnd;
  trace->ssthresh = sock->ssthresh;
  trace->cc_state = sock->cc_state;
}

void *begin_backend(void *in) {
  cmu_socket_t *sock = (cmu_socket_t *)in;
  int death, buf_len, send_signal;

  cc_log_open(sock);

  while (1) {
    if (sock->type == TCP_INITIATOR) {
      switch (sock->handshake_state) {
        case INIT:
          sock->isn = random_isn();
          sock->window.last_ack_received = sock->isn;
          send_empty_packet(sock, sock->window.last_ack_received,
                            sock->window.next_seq_expected, SYN_FLAG_MASK);
          clock_gettime(CLOCK_MONOTONIC, &sock->sent_syn_time);
          sock->handshake_state = SENT_SYN;
          break;
        case SENT_SYN:
          if (ms_since(&sock->sent_syn_time) > DEFAULT_TIMEOUT) {
            send_empty_packet(sock, sock->isn, 0, SYN_FLAG_MASK);
            clock_gettime(CLOCK_MONOTONIC, &sock->sent_syn_time);
          }
          break;
        default:
          break;
      }
    } else {
      switch (sock->handshake_state) {
        case RECEIVED_SYN:
          if (ms_since(&sock->sent_synack_time) > DEFAULT_TIMEOUT) {
            send_empty_packet(sock, sock->window.last_ack_received,
                              sock->window.next_seq_expected,
                              SYN_FLAG_MASK | ACK_FLAG_MASK);
            clock_gettime(CLOCK_MONOTONIC, &sock->sent_synack_time);
          }
          break;
        default:
          break;
      }
    }

    // Hold back data until the handshake is established.
    int can_send = sock->handshake_state == HANDSHAKE_ESTABLISHED;

    while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
    }
    death = sock->dying;
    pthread_mutex_unlock(&(sock->death_lock));

    while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
    }
    if (sock->sending_len > 0 && can_send) {
      // Move new data into the window buffer, where it stays until acked.
      sock->outbound_buf = realloc(sock->outbound_buf,
                                   sock->outbound_len + sock->sending_len);
      memcpy(sock->outbound_buf + sock->outbound_len, sock->sending_buf,
             sock->sending_len);
      sock->outbound_len += sock->sending_len;
      sock->sending_len = 0;
      free(sock->sending_buf);
      sock->sending_buf = NULL;
    }
    buf_len = sock->sending_len;
    pthread_mutex_unlock(&(sock->send_lock));

    // An empty sending_buf isn't enough: bytes may still be unacked.
    if (death && buf_len == 0 && sock->outbound_len == 0) {
      break;
    }

    if (can_send) {
      // Outgoing packets advertise our window, which reads received_len.
      while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
      }
      if (bytes_in_flight(sock) > 0 &&
          ms_since(&sock->sent_data_time) > DEFAULT_TIMEOUT) {
        if (sock->rwnd == 0) {
          // Peer's window is closed, not congested: just probe again.
          retransmit_oldest(sock, 1);
        } else {
          enter_slow_start(sock);
        }
      }
      single_send(sock);
      // We last advertised a zero window and cmu_read has since freed space.
      // The peer won't send until it hears, so send the new window.
      if (sock->sent_zero_window && advertised_window(sock) > 0) {
        send_empty_packet(sock, sock->window.last_ack_received,
                          sock->window.next_seq_expected, ACK_FLAG_MASK);
      }
      pthread_mutex_unlock(&(sock->recv_lock));
    }
    // Logged before reading a packet so a timeout's cut gets its own row.
    cc_log_write(sock);

    check_for_data(sock, TIMEOUT, LOOP_TICK_MS);
    cc_log_write(sock);

    while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
    }

    send_signal = sock->received_len > 0;

    pthread_mutex_unlock(&(sock->recv_lock));

    if (send_signal) {
      pthread_cond_signal(&(sock->wait_cond));
    }
  }

  if (sock->cc_log.file != NULL) {
    fclose(sock->cc_log.file);
  }
  pthread_exit(NULL);
  return NULL;
}
