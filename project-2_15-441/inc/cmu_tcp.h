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
 * This file defines the API for the CMU TCP implementation.
 */

#ifndef PROJECT_2_15_441_INC_CMU_TCP_H_
#define PROJECT_2_15_441_INC_CMU_TCP_H_

#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include "cmu_packet.h"
#include "grading.h"

#define EXIT_SUCCESS 0
#define EXIT_ERROR -1
#define EXIT_FAILURE 1

typedef struct {
  uint32_t next_seq_expected;
  uint32_t last_ack_received;  // Base: oldest unacked seq we sent.
  uint32_t next_seq_to_send;   // Seq of the next new byte; high-water mark.
} window_t;

/**
 * CMU-TCP socket types. (DO NOT CHANGE.)
 */
typedef enum {
  TCP_INITIATOR = 0,
  TCP_LISTENER = 1,
} cmu_socket_type_t;

/**
 * Handshake states. The initiator goes INIT -> SENT_SYN -> ESTABLISHED; the
 * listener goes INIT -> RECEIVED_SYN -> ESTABLISHED.
 */
typedef enum {
  INIT = 0,               // No SYN sent (initiator) or received (listener).
  SENT_SYN,               // Initiator: SYN sent, waiting for a valid SYN-ACK.
  RECEIVED_SYN,           // Listener: SYN-ACK sent, waiting for a valid ACK.
  HANDSHAKE_ESTABLISHED,  // Handshake complete from this side's view.
} handshake_state_t;

/**
 * TCP Reno congestion control states.
 */
typedef enum {
  SLOW_START = 0,
  CONGESTION_AVOIDANCE,
  FAST_RECOVERY,
} cc_state_t;

/**
 * A segment that arrived ahead of `next_seq_expected`. Kept in a list sorted
 * by seq until the gap before it is filled.
 */
typedef struct ooo_segment {
  uint32_t seq;
  uint16_t len;
  uint8_t* data;
  struct ooo_segment* next;
} ooo_segment_t;

/**
 * This structure holds the state of a socket. You may modify this structure as
 * you see fit to include any additional state you need for your implementation.
 */
typedef struct {
  int socket;
  pthread_t thread_id;
  uint16_t my_port;
  struct sockaddr_in conn;
  uint8_t* received_buf;
  int received_len;
  pthread_mutex_t recv_lock;
  pthread_cond_t wait_cond;
  uint8_t* sending_buf;
  int sending_len;
  cmu_socket_type_t type;
  pthread_mutex_t send_lock;
  int dying;
  pthread_mutex_t death_lock;
  window_t window;
  handshake_state_t handshake_state;
  uint32_t isn;                   // Our initial sequence number. Written once.
  struct timespec sent_syn_time;  // When the last SYN was sent (monotonic).
  struct timespec sent_synack_time;  // When the last SYN-ACK was sent.
  // Bytes from last_ack_received onward: in flight, then not yet sent. Backend
  // thread only, so no lock.
  uint8_t* outbound_buf;
  int outbound_len;
  struct timespec sent_data_time;  // Retransmit timer for the oldest segment.
  // Congestion and flow control. Backend thread only, so no lock.
  cc_state_t cc_state;
  uint32_t cwnd;           // Congestion window, in bytes.
  uint32_t ssthresh;       // Slow start threshold, in bytes.
  uint32_t dup_ack_count;  // Duplicate ACKs since the last new ACK.
  uint32_t rwnd;           // Peer's last advertised window, in bytes.
  // Segments received beyond a gap, guarded by recv_lock like received_buf.
  ooo_segment_t* ooo_head;
} cmu_socket_t;

/*
 * DO NOT CHANGE THE DECLARATIONS BELOW
 */

/**
 * Read mode flags supported by a CMU-TCP socket.
 */
typedef enum {
  NO_FLAG = 0,  // Default behavior: block indefinitely until data is available.
  NO_WAIT,      // Return immediately if no data is available.
  TIMEOUT,      // Block until data is available or the timeout is reached.
} cmu_read_mode_t;

/**
 * Constructs a CMU-TCP socket.
 *
 * An Initiator socket is used to connect to a Listener socket.
 *
 * @param sock The structure with the socket state. It will be initialized by
 *             this function.
 * @param socket_type Indicates the type of socket: Listener or Initiator.
 * @param port Port to either connect to, or bind to. (Based on socket_type.)
 * @param server_ip IP address of the server to connect to. (Only used if the
 *                 socket is an initiator.)
 *
 * @return 0 on success, -1 on error.
 */
int cmu_socket(cmu_socket_t* sock, const cmu_socket_type_t socket_type,
               const int port, const char* server_ip);

/**
 * Closes a CMU-TCP socket.
 *
 * @param sock The socket to close.
 *
 * @return 0 on success, -1 on error.
 */
int cmu_close(cmu_socket_t* sock);

/**
 * Reads data from a CMU-TCP socket.
 *
 * If there is data available in the socket buffer, it is placed in the
 * destination buffer.
 *
 * @param sock The socket to read from.
 * @param buf The buffer to read into.
 * @param length The maximum number of bytes to read.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information. `TIMEOUT` is not
 *             implemented for CMU-TCP.
 *
 * @return The number of bytes read on success, -1 on error.
 */
int cmu_read(cmu_socket_t* sock, void* buf, const int length,
             cmu_read_mode_t flags);

/**
 * Writes data to a CMU-TCP socket.
 *
 * @param sock The socket to write to.
 * @param buf The data to write.
 * @param length The number of bytes to write.
 *
 * @return 0 on success, -1 on error.
 */
int cmu_write(cmu_socket_t* sock, const void* buf, int length);

/*
 * You can declare more functions after this point if you need to.
 */

#endif  // PROJECT_2_15_441_INC_CMU_TCP_H_
