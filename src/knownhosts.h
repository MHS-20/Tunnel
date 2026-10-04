/* A minimal known_hosts store (OpenSSH format, plain host patterns only:
 * "host" for port 22, "[host]:port" otherwise; hashed and wildcard
 * entries are skipped). */
#ifndef TUNNEL_KNOWNHOSTS_H
#define TUNNEL_KNOWNHOSTS_H

#include <stdint.h>

typedef enum { KH_UNKNOWN, KH_MATCH, KH_MISMATCH } kh_result;

kh_result knownhosts_check(const char *file, const char *host, int port, const uint8_t pk[32]);
int knownhosts_add(const char *file, const char *host, int port, const uint8_t pk[32]);

#endif
