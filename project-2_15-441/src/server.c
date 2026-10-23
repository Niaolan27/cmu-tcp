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
 * This file implements a simple CMU-TCP server. Its purpose is to provide
 * simple test cases and demonstrate how the sockets will be used.
 *
 * Usage: ./server [output_file]
 *
 * Receives one file from the client and writes it to output_file (default:
 * /tmp/file.c).
 */

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "cmu_tcp.h"

#define DEFAULT_OUTPUT "/tmp/file.c"
// At least the receive buffer's size, so one read can drain it.
#define BUF_SIZE 65536

/*
 * Reads exactly `len` bytes; cmu_read returns whatever has arrived so far.
 */
static void read_exact(cmu_socket_t *sock, uint8_t *buf, int len) {
  int got = 0;
  while (got < len) {
    got += cmu_read(sock, buf + got, len - got, NO_FLAG);
  }
}

/*
 * Param: sock - used for reading and writing to a connection
 * Param: output - where to write the received file
 *
 * Purpose: Receives a 4-byte length in network byte order, then that many
 *  bytes of file contents.
 *
 */
void functionality(cmu_socket_t *sock, const char *output) {
  static uint8_t buf[BUF_SIZE];
  uint32_t size_net, size, received = 0, next_report;
  FILE *fp;
  int n;

  read_exact(sock, (uint8_t *)&size_net, sizeof(size_net));
  size = ntohl(size_net);
  printf("Receiving %u bytes\n", size);
  next_report = size / 10;

  fp = fopen(output, "wb");
  if (fp == NULL) {
    perror(output);
    exit(EXIT_FAILURE);
  }
  while (received < size) {
    n = size - received < BUF_SIZE ? (int)(size - received) : BUF_SIZE;
    n = cmu_read(sock, buf, n, NO_FLAG);
    fwrite(buf, 1, n, fp);
    received += n;
    if (received >= next_report) {
      printf("%3u%%  %u bytes\n", (uint32_t)(100ULL * received / size),
             received);
      fflush(stdout);
      next_report += size / 10;
    }
  }
  fclose(fp);

  // Without a FIN, the client learns the transfer is done only from our
  // ACKs. Stay up for a few retransmission timeouts so that if the final ACK
  // is lost, the client's retransmission still gets acknowledged.
  sleep((3 * DEFAULT_TIMEOUT + 999) / 1000);
}

int main(int argc, char *argv[]) {
  int portno;
  char *serverip;
  char *serverport;
  const char *output = argc > 1 ? argv[1] : DEFAULT_OUTPUT;
  cmu_socket_t socket;

  serverip = getenv("server15441");
  if (!serverip) {
    serverip = "10.0.1.1";
  }

  serverport = getenv("serverport15441");
  if (!serverport) {
    serverport = "15441";
  }
  portno = (uint16_t)atoi(serverport);

  if (cmu_socket(&socket, TCP_LISTENER, portno, serverip) < 0) {
    exit(EXIT_FAILURE);
  }

  functionality(&socket, output);

  if (cmu_close(&socket) < 0) {
    exit(EXIT_FAILURE);
  }

  return EXIT_SUCCESS;
}
