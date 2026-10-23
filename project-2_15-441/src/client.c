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
 * This file implements a simple CMU-TCP client. Its purpose is to provide
 * simple test cases and demonstrate how the sockets will be used.
 *
 * Usage: ./client [input_file]
 *
 * Sends input_file (default: src/cmu_tcp.c) to the server, then reports how
 * long the transfer took. Set CWND_LOG=<path> to trace congestion control.
 */

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>

#include "cmu_tcp.h"

#define DEFAULT_INPUT "/vagrant/project-2_15-441/src/cmu_tcp.c"
#define CHUNK_SIZE 65536

/*
 * Param: sock - used for reading and writing to a connection
 * Param: fp - the file to send
 * Param: size - the file's length in bytes
 *
 * Purpose: Sends the file's length as 4 bytes in network byte order, then its
 *  contents. The server needs the length because there is no FIN to mark the
 *  end of the stream.
 *
 */
void functionality(cmu_socket_t *sock, FILE *fp, uint32_t size) {
  static uint8_t buf[CHUNK_SIZE];
  uint32_t size_net = htonl(size);
  size_t read;

  cmu_write(sock, &size_net, sizeof(size_net));
  while ((read = fread(buf, 1, CHUNK_SIZE, fp)) > 0) {
    cmu_write(sock, buf, read);
  }
}

int main(int argc, char *argv[]) {
  int portno;
  char *serverip;
  char *serverport;
  const char *input = argc > 1 ? argv[1] : DEFAULT_INPUT;
  cmu_socket_t socket;
  FILE *fp;
  struct stat st;
  uint32_t size;
  struct timespec start, end;
  double elapsed;

  fp = fopen(input, "rb");
  if (fp == NULL || fstat(fileno(fp), &st) < 0) {
    perror(input);
    exit(EXIT_FAILURE);
  }
  // The length prefix is 32 bits, so files must be under 4 GiB.
  size = (uint32_t)st.st_size;

  serverip = getenv("server15441");
  if (!serverip) {
    serverip = "10.0.1.1";
  }

  serverport = getenv("serverport15441");
  if (!serverport) {
    serverport = "15441";
  }
  portno = (uint16_t)atoi(serverport);

  clock_gettime(CLOCK_MONOTONIC, &start);
  if (cmu_socket(&socket, TCP_INITIATOR, portno, serverip) < 0) {
    exit(EXIT_FAILURE);
  }

  functionality(&socket, fp, size);
  fclose(fp);

  // cmu_close returns once every byte has been acknowledged.
  if (cmu_close(&socket) < 0) {
    exit(EXIT_FAILURE);
  }
  clock_gettime(CLOCK_MONOTONIC, &end);

  elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
  printf("Sent %u bytes in %.2f s (%.1f KB/s)\n", size, elapsed,
         size / 1024.0 / elapsed);

  return EXIT_SUCCESS;
}
