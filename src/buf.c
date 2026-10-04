#include "buf.h"

#include <stdlib.h>
#include <string.h>

void wbuf_init(wbuf *w) { memset(w, 0, sizeof *w); }

void wbuf_free(wbuf *w)
{
	if (w->data)
		memset(w->data, 0, w->cap);
	free(w->data);
	wbuf_init(w);
}

void wbuf_reset(wbuf *w)
{
	w->len = 0;
	w->err = 0;
}

uint8_t *wbuf_reserve(wbuf *w, size_t n)
{
	if (w->err || n > BUF_MAX - w->len) {
		w->err = 1;
		return NULL;
	}
	if (w->len + n > w->cap) {
		size_t cap = w->cap ? w->cap : 256;
		while (cap < w->len + n)
			cap *= 2;
		uint8_t *d = realloc(w->data, cap);
		if (!d) {
			w->err = 1;
			return NULL;
		}
		w->data = d;
		w->cap = cap;
	}
	uint8_t *p = w->data + w->len;
	w->len += n;
	return p;
}

uint32_t peek_u32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

void poke_u32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >> 8;
	p[3] = v;
}

void put_raw(wbuf *w, const void *p, size_t n)
{
	uint8_t *d = wbuf_reserve(w, n);
	if (d && n)
		memcpy(d, p, n);
}

void put_u8(wbuf *w, uint8_t v) { put_raw(w, &v, 1); }

void put_u32(wbuf *w, uint32_t v)
{
	uint8_t b[4];
	poke_u32(b, v);
	put_raw(w, b, 4);
}

void put_bool(wbuf *w, int v) { put_u8(w, v ? 1 : 0); }

void put_string(wbuf *w, const void *p, size_t n)
{
	if (n > UINT32_MAX) {
		w->err = 1;
		return;
	}
	put_u32(w, (uint32_t)n);
	put_raw(w, p, n);
}

void put_cstring(wbuf *w, const char *s) { put_string(w, s, strlen(s)); }

/* RFC 4251 5: two's complement, minimal length; a positive value whose
 * top bit is set gets a leading zero byte. */
void put_mpint(wbuf *w, const uint8_t *be, size_t n)
{
	while (n > 0 && be[0] == 0) {
		be++;
		n--;
	}
	int pad = n > 0 && (be[0] & 0x80);
	put_u32(w, (uint32_t)(n + pad));
	if (pad)
		put_u8(w, 0);
	put_raw(w, be, n);
}

void rbuf_init(rbuf *r, const void *p, size_t n)
{
	r->data = p;
	r->len = n;
	r->off = 0;
	r->err = 0;
}

size_t rbuf_left(const rbuf *r) { return r->len - r->off; }

const uint8_t *get_raw(rbuf *r, size_t n)
{
	if (r->err || n > rbuf_left(r)) {
		r->err = 1;
		return NULL;
	}
	const uint8_t *p = r->data + r->off;
	r->off += n;
	return p;
}

uint8_t get_u8(rbuf *r)
{
	const uint8_t *p = get_raw(r, 1);
	return p ? p[0] : 0;
}

uint32_t get_u32(rbuf *r)
{
	const uint8_t *p = get_raw(r, 4);
	return p ? peek_u32(p) : 0;
}

int get_bool(rbuf *r) { return get_u8(r) != 0; }

const uint8_t *get_string(rbuf *r, uint32_t *n)
{
	uint32_t len = get_u32(r);
	const uint8_t *p = get_raw(r, len);
	*n = p ? len : 0;
	return p;
}

int get_cstring(rbuf *r, char *out, size_t cap)
{
	uint32_t n;
	const uint8_t *p = get_string(r, &n);
	if (!p || n >= cap || memchr(p, 0, n)) {
		r->err = 1;
		if (cap)
			out[0] = 0;
		return -1;
	}
	memcpy(out, p, n);
	out[n] = 0;
	return 0;
}
