#include "kex.h"

#include <sodium.h>

void kex_c25519_keygen(uint8_t pub[32], uint8_t priv[32])
{
	randombytes_buf(priv, 32);
	crypto_scalarmult_base(pub, priv);
}

int kex_c25519_shared(wbuf *k, const uint8_t priv[32], const uint8_t peer[32])
{
	uint8_t x[32];
	/* libsodium returns -1 for an all-zero result (RFC 8731 section 3). */
	if (crypto_scalarmult(x, priv, peer) != 0)
		return -1;
	/* RFC 8731: the 32 bytes are interpreted as a big-endian integer. */
	put_mpint(k, x, sizeof x);
	sodium_memzero(x, sizeof x);
	return k->err ? -1 : 0;
}

void kex_exchange_hash(const kex_hash_input *in, uint8_t H[32])
{
	wbuf w;
	wbuf_init(&w);
	put_cstring(&w, in->v_c);
	put_cstring(&w, in->v_s);
	put_string(&w, in->i_c->data, in->i_c->len);
	put_string(&w, in->i_s->data, in->i_s->len);
	put_string(&w, in->k_s, in->k_s_len);
	put_string(&w, in->q_c, 32);
	put_string(&w, in->q_s, 32);
	put_raw(&w, in->k->data, in->k->len);
	crypto_hash_sha256(H, w.data, w.len);
	wbuf_free(&w);
}
