/* SSH_MSG_KEXINIT and algorithm negotiation (RFC 4253 section 7.1). */
#ifndef TUNNEL_KEXINIT_H
#define TUNNEL_KEXINIT_H

#include <stddef.h>
#include <stdint.h>

#include "buf.h"

enum {
	KI_KEX, KI_HOSTKEY,
	KI_ENC_CS, KI_ENC_SC,
	KI_MAC_CS, KI_MAC_SC,
	KI_COMP_CS, KI_COMP_SC,
	KI_LANG_CS, KI_LANG_SC,
	KI_NLISTS
};

#define ALG_NAME_MAX 64

typedef struct {
	uint8_t cookie[16];
	char *lists[KI_NLISTS]; /* heap-owned name-lists */
	int first_kex_follows;
} kexinit;

typedef struct {
	char kex[ALG_NAME_MAX], hostkey[ALG_NAME_MAX];
	char enc_cs[ALG_NAME_MAX], enc_sc[ALG_NAME_MAX];
	char mac_cs[ALG_NAME_MAX], mac_sc[ALG_NAME_MAX]; /* "" for AEAD */
	char comp_cs[ALG_NAME_MAX], comp_sc[ALG_NAME_MAX];
	int guess_wrong; /* discard the peer's guessed first kex packet */
} kex_algs;

/* Fills a kexinit from string lists with a fresh random cookie. */
int kexinit_new(kexinit *k, const char *const lists[KI_NLISTS]);
void kexinit_free(kexinit *k);
void kexinit_encode(const kexinit *k, wbuf *w); /* full payload, msg byte first */
int kexinit_decode(const uint8_t *p, size_t n, kexinit *k);

int namelist_contains(const char *list, const char *name);
/* First entry of `client` that also appears in `server`. */
int namelist_choose(const char *client, const char *server, char *out, size_t cap);
int kexinit_negotiate(const kexinit *client, const kexinit *server, kex_algs *out);

#endif
