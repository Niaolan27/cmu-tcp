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
 * Updates the socket information to represent the newly received packet.
 *
 * In the current stop-and-wait implementation, this function also sends an
 * acknowledgement for the packet.
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
        sock->isn = (uint32_t)rand();
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
      // Validate against last_ack_received before the update below moves it.
      if (sock->handshake_state == RECEIVED_SYN && check_valid_ack(sock, hdr)) {
        sock->handshake_state = HANDSHAKE_ESTABLISHED;
      }
      uint32_t ack = get_ack(hdr);
      if (after(ack, sock->window.last_ack_received)) {
        sock->window.last_ack_received = ack;
      }
      break;
    }
    default: {
      // Ignore data until the handshake is established.
      if (sock->handshake_state != HANDSHAKE_ESTABLISHED) {
        break;
      }
      socklen_t conn_len = sizeof(sock->conn);
      uint32_t seq = sock->window.last_ack_received;

      // No payload.
      uint8_t *payload = NULL;
      uint16_t payload_len = 0;

      // No extension.
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;

      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t ack = get_seq(hdr) + get_payload_len(pkt);
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = ACK_FLAG_MASK;
      uint16_t adv_window = 1;
      uint8_t *response_packet =
          create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                        ext_len, ext_data, payload, payload_len);

      sendto(sock->socket, response_packet, plen, 0,
             (struct sockaddr *)&(sock->conn), conn_len);
      free(response_packet);

      seq = get_seq(hdr);

      if (seq == sock->window.next_seq_expected) {
        sock->window.next_seq_expected = seq + get_payload_len(pkt);
        payload_len = get_payload_len(pkt);
        payload = get_payload(pkt);

        // Make sure there is enough space in the buffer to store the payload.
        sock->received_buf =
            realloc(sock->received_buf, sock->received_len + payload_len);
        memcpy(sock->received_buf + sock->received_len, payload, payload_len);
        sock->received_len += payload_len;
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

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }
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
    handle_message(sock, pkt);
    free(pkt);
  }
  pthread_mutex_unlock(&(sock->recv_lock));
}

/**
 * Breaks up the data into packets and sends a single packet at a time.
 *
 * You should most certainly update this function in your implementation.
 *
 * @param sock The socket to use for sending data.
 * @param data The data to be sent.
 * @param buf_len The length of the data being sent.
 */
void single_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {
  uint8_t *msg;
  uint8_t *data_offset = data;
  size_t conn_len = sizeof(sock->conn);

  int sockfd = sock->socket;
  if (buf_len > 0) {
    while (buf_len != 0) {
      uint16_t payload_len = MIN((uint32_t)buf_len, (uint32_t)MSS);

      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t seq = sock->window.last_ack_received;
      uint32_t ack = sock->window.next_seq_expected;
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = 0;
      uint16_t adv_window = 1;
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;
      uint8_t *payload = data_offset;

      msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                          ext_len, ext_data, payload, payload_len);
      buf_len -= payload_len;

      while (1) {
        // FIXME: This is using stop and wait, can we do better?
        sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn),
               conn_len);
        check_for_data(sock, TIMEOUT, DEFAULT_TIMEOUT);
        if (has_been_acked(sock, seq)) {
          break;
        }
      }
      free(msg);

      data_offset += payload_len;
    }
  }
}

void *begin_backend(void *in) {
  cmu_socket_t *sock = (cmu_socket_t *)in;
  int death, buf_len, send_signal;
  uint8_t *data;

  while (1) {
    if (sock->type == TCP_INITIATOR) {
      switch (sock->handshake_state) {
        case INIT:
          sock->isn = (uint32_t)rand();
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
    buf_len = sock->sending_len;

    if (death && buf_len == 0) {
      break;
    }

    if (buf_len > 0 && can_send) {
      data = malloc(buf_len);
      memcpy(data, sock->sending_buf, buf_len);
      sock->sending_len = 0;
      free(sock->sending_buf);
      sock->sending_buf = NULL;
      pthread_mutex_unlock(&(sock->send_lock));
      single_send(sock, data, buf_len);
      free(data);
    } else {
      pthread_mutex_unlock(&(sock->send_lock));
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
