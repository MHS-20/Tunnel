/* Server-side authorized_keys lookup (plain lines, no options). */
#ifndef TUNNEL_AUTHKEYS_H
#define TUNNEL_AUTHKEYS_H

#include <stdint.h>

int authkeys_allowed(const char *file, const uint8_t pk[32]);

#endif
