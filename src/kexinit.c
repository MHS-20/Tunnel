#include "kexinit.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>

#include "cipher.h"
#include "ssh_msg.h"

int kexinit_new(kexinit *k, const char *const lists[KI_NLISTS])
{
	memset(k, 0, sizeof *k);
	randombytes_buf(k->cookie, sizeof k->cookie);
	for (int i = 0; i < KI_NLISTS; i++)
		if (!(k->lists[i] = strdup(lists[i]))) {
			kexinit_free(k);
			return -1;
		}
	return 0;
}

void kexinit_free(kexinit *k)
{
	for (int i = 0; i < KI_NLISTS; i++)
		free(k->lists[i]);
	memset(k, 0, sizeof *k);
}

void kexinit_encode(const kexinit *k, wbuf *w)
{
	put_u8(w, SSH_MSG_KEXINIT);
	put_raw(w, k->cookie, sizeof k->cookie);
	for (int i = 0; i < KI_NLISTS; i++)
		put_cstring(w, k->lists[i]);
	put_bool(w, k->first_kex_follows);
	put_u32(w, 0); /* reserved */
}

int kexinit_decode(const uint8_t *p, size_t n, kexinit *k)
{
	rbuf r;
	memset(k, 0, sizeof *k);
	rbuf_init(&r, p, n);
	if (get_u8(&r) != SSH_MSG_KEXINIT)
		return -1;
	const uint8_t *cookie = get_raw(&r, sizeof k->cookie);
	if (cookie)
		memcpy(k->cookie, cookie, sizeof k->cookie);
	for (int i = 0; i < KI_NLISTS && !r.err; i++) {
		uint32_t len;
		const uint8_t *s = get_string(&r, &len);
		if (!s || memchr(s, 0, len) || !(k->lists[i] = strndup((const char *)s, len)))
			r.err = 1;
	}
	k->first_kex_follows = get_bool(&r);
	get_u32(&r);
	if (r.err) {
		kexinit_free(k);
		return -1;
	}
	return 0;
}

/* Calls fn on each comma-separated entry until it returns nonzero. */
static int namelist_each(const char *list, int (*fn)(const char *, size_t, void *), void *arg)
{
	for (const char *p = list; *p;) {
		size_t n = strcspn(p, ",");
		if (n > 0 && fn(p, n, arg))
			return 1;
		p += n;
		if (*p == ',')
			p++;
	}
	return 0;
}

struct needle { const char *s; size_t n; };

static int match_needle(const char *p, size_t n, void *arg)
{
	const struct needle *nd = arg;
	return n == nd->n && memcmp(p, nd->s, n) == 0;
}

int namelist_contains(const char *list, const char *name)
{
	struct needle nd = {name, strlen(name)};
	return namelist_each(list, match_needle, &nd);
}

struct choice { const char *server; char *out; size_t cap; };

static int pick_if_server_has(const char *p, size_t n, void *arg)
{
	struct choice *c = arg;
	struct needle nd = {p, n};
	if (n >= c->cap || !namelist_each(c->server, match_needle, &nd))
		return 0;
	memcpy(c->out, p, n);
	c->out[n] = 0;
	return 1;
}

int namelist_choose(const char *client, const char *server, char *out, size_t cap)
{
	struct choice c = {server, out, cap};
	return namelist_each(client, pick_if_server_has, &c) ? 0 : -1;
}

static int first_entries_equal(const char *a, const char *b)
{
	size_t na = strcspn(a, ","), nb = strcspn(b, ",");
	return na == nb && memcmp(a, b, na) == 0;
}

#define CHOOSE(field, idx) \
	namelist_choose(c->lists[idx], s->lists[idx], out->field, sizeof out->field)

int kexinit_negotiate(const kexinit *c, const kexinit *s, kex_algs *out)
{
	cipher_kind ck;
	memset(out, 0, sizeof *out);
	if (CHOOSE(kex, KI_KEX) || CHOOSE(hostkey, KI_HOSTKEY) ||
	    CHOOSE(enc_cs, KI_ENC_CS) || CHOOSE(enc_sc, KI_ENC_SC) ||
	    CHOOSE(comp_cs, KI_COMP_CS) || CHOOSE(comp_sc, KI_COMP_SC))
		return -1;
	/* An AEAD cipher carries its own tag; the MAC lists are not consulted
	 * (as OpenSSH does). We only support AEAD ciphers. */
	if (cipher_by_name(out->enc_cs, &ck) || cipher_tag_len(&(cipher_ctx){.kind = ck}) == 0 ||
	    cipher_by_name(out->enc_sc, &ck) || cipher_tag_len(&(cipher_ctx){.kind = ck}) == 0)
		return -1;
	const kexinit *guesser = c->first_kex_follows ? c : s->first_kex_follows ? s : NULL;
	if (guesser)
		out->guess_wrong = !first_entries_equal(c->lists[KI_KEX], s->lists[KI_KEX]) ||
				   !first_entries_equal(c->lists[KI_HOSTKEY], s->lists[KI_HOSTKEY]);
	return 0;
}
