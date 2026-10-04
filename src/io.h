/* Blocking full-length reads and writes on a file descriptor. */
#ifndef TUNNEL_IO_H
#define TUNNEL_IO_H

#include <stddef.h>

int read_full(int fd, void *p, size_t n);        /* 0 ok, -1 error/EOF */
int write_full(int fd, const void *p, size_t n); /* 0 ok, -1 error */

#endif
