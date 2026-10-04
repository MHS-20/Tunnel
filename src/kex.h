/* curve25519-sha256 key exchange (RFC 8731) and the exchange hash H
 * (RFC 5656 section 4 layout, as RFC 8731 specifies). */
#ifndef TUNNEL_KEX_H
#define TUNNEL_KEX_H

#include <stddef.h>
#include <stdint.h>

#include "buf.h"

#define KEX_CURVE25519 "curve25519-sha256"
#define KEX_CURVE25519_LIBSSH "curve25519-sha256@libssh.org"
#define KEX_STRICT_C "kex-strict-c-v00@openssh.com"
#define KEX_STRICT_S "kex-strict-s-v00@openssh.com"

void kex_c25519_keygen(uint8_t pub[32], uint8_t priv[32]);
/* Shared secret X25519(priv, peer), encoded as an mpint into k.
 * Fails on the all-zero output (low-order peer point). */
int kex_c25519_shared(wbuf *k, const uint8_t priv[32], const uint8_t peer[32]);

typedef struct {
	const char *v_c, *v_s;          /* identification strings, no CR LF */
	const wbuf *i_c, *i_s;          /* KEXINIT payloads */
	const uint8_t *k_s; size_t k_s_len; /* server host key blob */
	const uint8_t *q_c, *q_s;       /* ephemeral public keys, 32 bytes */
	const wbuf *k;                  /* shared secret as mpint */
} kex_hash_input;

void kex_exchange_hash(const kex_hash_input *in, uint8_t H[32]);

#endif
