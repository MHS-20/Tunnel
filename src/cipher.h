/* Packet ciphers: "none" (before the first NEWKEYS) and
 * chacha20-poly1305@openssh.com (OpenSSH PROTOCOL.chacha20poly1305).
 *
 * The packet layer only sees this interface: decrypt the 4-byte length
 * early, then authenticate-and-decrypt (or encrypt-and-tag) the rest. */
#ifndef TUNNEL_CIPHER_H
#define TUNNEL_CIPHER_H

#include <stddef.h>
#include <stdint.h>

#define CIPHER_CHACHAPOLY_NAME "chacha20-poly1305@openssh.com"
#define CIPHER_KEY_MAX 64
#define CIPHER_TAG_MAX 16

typedef enum { CIPHER_NONE, CIPHER_CHACHAPOLY } cipher_kind;

typedef struct {
	cipher_kind kind;
	uint8_t key[CIPHER_KEY_MAX];
} cipher_ctx;

int cipher_by_name(const char *name, cipher_kind *out);
size_t cipher_key_len(cipher_kind k);
void cipher_init(cipher_ctx *c, cipher_kind k, const uint8_t *key);
size_t cipher_block_size(const cipher_ctx *c);
size_t cipher_tag_len(const cipher_ctx *c);
/* True when the length field is excluded from padding alignment. */
int cipher_length_is_aad(const cipher_ctx *c);

uint32_t cipher_peek_length(const cipher_ctx *c, uint32_t seq, const uint8_t enc[4]);
/* pkt holds length||body (n bytes, n >= 4); encrypted in place. */
void cipher_seal(const cipher_ctx *c, uint32_t seq, uint8_t *pkt, size_t n,
		 uint8_t tag[CIPHER_TAG_MAX]);
/* Verifies tag, then decrypts in place. -1 on authentication failure. */
int cipher_open(const cipher_ctx *c, uint32_t seq, uint8_t *pkt, size_t n,
		const uint8_t tag[CIPHER_TAG_MAX]);

#endif
