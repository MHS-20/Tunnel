/* Protocol version exchange (RFC 4253 section 4.2). */
#ifndef TUNNEL_VERSION_H
#define TUNNEL_VERSION_H

#include <stddef.h>

#define TUNNEL_IDENT "SSH-2.0-Tunnel_0.1"
#define VERSION_MAX 255 /* including CR LF */

int version_send(int fd, const char *ident);
/* Reads lines until one starts with "SSH-"; stores it without CR LF.
 * Accepts protocol 2.0 and the compatibility value 1.99. */
int version_recv(int fd, char *out, size_t cap);
/* Validates a single identification line (no CR LF). */
int version_check(const char *line);

#endif
