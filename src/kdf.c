#include "kdf.h"

#include <sodium.h>
#include <string.h>

void kdf_derive(const uint8_t *k_mpint, size_t k_len, const uint8_t H[KDF_HASH_LEN],
		char letter, const uint8_t session_id[KDF_HASH_LEN], uint8_t *out, size_t out_len)
{
	uint8_t block[KDF_HASH_LEN];
	crypto_hash_sha256_state st;
	size_t have = 0;

	while (have < out_len) {
		crypto_hash_sha256_init(&st);
		crypto_hash_sha256_update(&st, k_mpint, k_len);
		crypto_hash_sha256_update(&st, H, KDF_HASH_LEN);
		if (have == 0) {
			uint8_t x = (uint8_t)letter;
			crypto_hash_sha256_update(&st, &x, 1);
			crypto_hash_sha256_update(&st, session_id, KDF_HASH_LEN);
		} else {
			crypto_hash_sha256_update(&st, out, have);
		}
		crypto_hash_sha256_final(&st, block);
		size_t n = out_len - have < KDF_HASH_LEN ? out_len - have : KDF_HASH_LEN;
		memcpy(out + have, block, n);
		have += n;
	}
	sodium_memzero(block, sizeof block);
}
