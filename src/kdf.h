/* Key derivation (RFC 4253 section 7.2), SHA-256 as the exchange hash:
 *   K1 = HASH(K || H || letter || session_id)
 *   Kn = HASH(K || H || K1 || ... || K(n-1))
 * where K is the shared secret already encoded as an mpint. */
#ifndef TUNNEL_KDF_H
#define TUNNEL_KDF_H

#include <stddef.h>
#include <stdint.h>

#define KDF_HASH_LEN 32

void kdf_derive(const uint8_t *k_mpint, size_t k_len, const uint8_t H[KDF_HASH_LEN],
		char letter, const uint8_t session_id[KDF_HASH_LEN], uint8_t *out, size_t out_len);

#endif
