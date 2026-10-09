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
  uint16_t adv_window = 1;
  uint8_t *pkt = create_packet(src, dst, seq, ack, hlen, plen, flags,
                               adv_window, 0, NULL, NULL, 0);

  sendto(sock->socket, pkt, plen, 0, (struct sockaddr *)&(sock->conn),
         conn_len);
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
  uint16_t adv_window = 1;
  uint8_t *pkt = create_packet(src, dst, seq, ack, hlen, plen, flags,
                               adv_window, 0, NULL, payload, payload_len);

  sendto(sock->socket, pkt, plen, 0, (struct sockaddr *)&(sock->conn),
         conn_len);
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
 * Slides the send window for an acknowledgement received after the handshake.
 * Old or duplicate ACKs (ack <= base) and ACKs for bytes never sent
 * (ack > next_seq_to_send) are ignored.
 *
 * @param sock The socket whose window to slide.
 * @param ack The acknowledgement number received.
 */
static void handle_ack(cmu_socket_t *sock, uint32_t ack) {
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
}

/**
 * Accepts a data packet's payload if it is the next in-order segment, discards
 * it otherwise, and answers either way with a cumulative acknowledgement.
 *
 * @param sock The socket receiving the data.
 * @param pkt The data packet.
 */
static void handle_data(cmu_socket_t *sock, uint8_t *pkt) {
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  uint32_t seq = get_seq(hdr);
  uint16_t payload_len = get_payload_len(pkt);

  if (seq == sock->window.next_seq_expected) {
    sock->window.next_seq_expected = seq + payload_len;
    uint8_t *payload = get_payload(pkt);

    // Make sure there is enough space in the buffer to store the payload.
    sock->received_buf =
        realloc(sock->received_buf, sock->received_len + payload_len);
    memcpy(sock->received_buf + sock->received_len, payload, payload_len);
    sock->received_len += payload_len;
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
        handle_ack(sock, ack);
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
 * @param sock The socket to use for sending data.
 */
void single_send(cmu_socket_t *sock) {
  uint32_t window = CP1_WINDOW_SIZE;
  uint32_t outbound_len = sock->outbound_len;
  uint32_t in_flight = bytes_in_flight(sock);

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
 * Go-Back-N retransmission: resends every unacknowledged byte, oldest first,
 * and restarts the retransmit timer. Leaves `next_seq_to_send` alone.
 *
 * @param sock The socket to use for sending data.
 */
static void resend_window(cmu_socket_t *sock) {
  uint32_t in_flight = bytes_in_flight(sock);
  uint32_t offset = 0;

  while (offset < in_flight) {
    uint16_t payload_len = MIN((uint32_t)MSS, in_flight - offset);
    send_data_segment(sock, sock->window.last_ack_received + offset,
                      sock->outbound_buf + offset, payload_len);
    offset += payload_len;
  }
  clock_gettime(CLOCK_MONOTONIC, &sock->sent_data_time);
}

void *begin_backend(void *in) {
  cmu_socket_t *sock = (cmu_socket_t *)in;
  int death, buf_len, send_signal;

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
      if (bytes_in_flight(sock) > 0 &&
          ms_since(&sock->sent_data_time) > DEFAULT_TIMEOUT) {
        resend_window(sock);
      }
      single_send(sock);
    }

    check_for_data(sock, TIMEOUT, LOOP_TICK_MS);

    while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
    }

    send_signal = sock->received_len > 0;

    pthread_mutex_unlock(&(sock->recv_lock));

    if (send_signal) {
      pthread_cond_signal(&(sock->wait_cond));
    }
  }

  pthread_exit(NULL);
  return NULL;
}
