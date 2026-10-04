#include "cipher.h"

#include <sodium.h>
#include <string.h>

/* chacha20-poly1305@openssh.com: the 64-byte key is K_main || K_header.
 * Nonce is the packet sequence number as a 64-bit big-endian value and
 * the original (64-bit nonce) ChaCha20 is used, which is exactly
 * libsodium's crypto_stream_chacha20 family.
 *   - length:   K_header, counter 0
 *   - poly key: first 32 bytes of K_main keystream block 0
 *   - payload:  K_main, counter 1
 *   - tag:      Poly1305 over ciphertext length || ciphertext payload */

static void seq_nonce(uint8_t n[8], uint32_t seq)
{
	memset(n, 0, 4);
	n[4] = seq >> 24;
	n[5] = seq >> 16;
	n[6] = seq >> 8;
	n[7] = seq;
}

static void poly_key(const cipher_ctx *c, const uint8_t nonce[8], uint8_t pk[32])
{
	crypto_stream_chacha20(pk, 32, nonce, c->key);
}

int cipher_by_name(const char *name, cipher_kind *out)
{
	if (strcmp(name, CIPHER_CHACHAPOLY_NAME) == 0) {
		*out = CIPHER_CHACHAPOLY;
		return 0;
	}
	return -1;
}

size_t cipher_key_len(cipher_kind k) { return k == CIPHER_CHACHAPOLY ? 64 : 0; }

void cipher_init(cipher_ctx *c, cipher_kind k, const uint8_t *key)
{
	memset(c, 0, sizeof *c);
	c->kind = k;
	if (key)
		memcpy(c->key, key, cipher_key_len(k));
}

size_t cipher_block_size(const cipher_ctx *c) { (void)c; return 8; }

size_t cipher_tag_len(const cipher_ctx *c) { return c->kind == CIPHER_CHACHAPOLY ? 16 : 0; }

int cipher_length_is_aad(const cipher_ctx *c) { return c->kind == CIPHER_CHACHAPOLY; }

uint32_t cipher_peek_length(const cipher_ctx *c, uint32_t seq, const uint8_t enc[4])
{
	uint8_t plain[4], nonce[8];
	if (c->kind == CIPHER_NONE)
		return (uint32_t)enc[0] << 24 | (uint32_t)enc[1] << 16 | (uint32_t)enc[2] << 8 | enc[3];
	seq_nonce(nonce, seq);
	crypto_stream_chacha20_xor_ic(plain, enc, 4, nonce, 0, c->key + 32);
	return (uint32_t)plain[0] << 24 | (uint32_t)plain[1] << 16 | (uint32_t)plain[2] << 8 | plain[3];
}

void cipher_seal(const cipher_ctx *c, uint32_t seq, uint8_t *pkt, size_t n,
		 uint8_t tag[CIPHER_TAG_MAX])
{
	uint8_t nonce[8], pk[32];
	if (c->kind == CIPHER_NONE)
		return;
	seq_nonce(nonce, seq);
	crypto_stream_chacha20_xor_ic(pkt, pkt, 4, nonce, 0, c->key + 32);
	crypto_stream_chacha20_xor_ic(pkt + 4, pkt + 4, n - 4, nonce, 1, c->key);
	poly_key(c, nonce, pk);
	crypto_onetimeauth_poly1305(tag, pkt, n, pk);
	sodium_memzero(pk, sizeof pk);
}

int cipher_open(const cipher_ctx *c, uint32_t seq, uint8_t *pkt, size_t n,
		const uint8_t tag[CIPHER_TAG_MAX])
{
	uint8_t nonce[8], pk[32];
	if (c->kind == CIPHER_NONE)
		return 0;
	seq_nonce(nonce, seq);
	poly_key(c, nonce, pk);
	int bad = crypto_onetimeauth_poly1305_verify(tag, pkt, n, pk);
	sodium_memzero(pk, sizeof pk);
	if (bad)
		return -1;
	crypto_stream_chacha20_xor_ic(pkt, pkt, 4, nonce, 0, c->key + 32);
	crypto_stream_chacha20_xor_ic(pkt + 4, pkt + 4, n - 4, nonce, 1, c->key);
	return 0;
}
