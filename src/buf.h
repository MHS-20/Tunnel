/* SSH wire encoding (RFC 4251 section 5) over bounded buffers.
 *
 * Writers grow up to BUF_MAX; readers never read past their slice.
 * Both carry a sticky error flag so callers can encode/decode a whole
 * message and check once at the end. */
#ifndef TUNNEL_BUF_H
#define TUNNEL_BUF_H

#include <stddef.h>
#include <stdint.h>

#define BUF_MAX (256 * 1024)

typedef struct {
	uint8_t *data;
	size_t len, cap;
	int err;
} wbuf;

typedef struct {
	const uint8_t *data;
	size_t len, off;
	int err;
} rbuf;

void wbuf_init(wbuf *w);
void wbuf_free(wbuf *w);
void wbuf_reset(wbuf *w);
uint8_t *wbuf_reserve(wbuf *w, size_t n); /* append n bytes, return them */

void put_u8(wbuf *w, uint8_t v);
void put_u32(wbuf *w, uint32_t v);
void put_bool(wbuf *w, int v);
void put_raw(wbuf *w, const void *p, size_t n);
void put_string(wbuf *w, const void *p, size_t n);
void put_cstring(wbuf *w, const char *s); /* also used for name-lists */
void put_mpint(wbuf *w, const uint8_t *be, size_t n); /* unsigned magnitude */

void rbuf_init(rbuf *r, const void *p, size_t n);
size_t rbuf_left(const rbuf *r);
uint8_t get_u8(rbuf *r);
uint32_t get_u32(rbuf *r);
int get_bool(rbuf *r);
const uint8_t *get_raw(rbuf *r, size_t n);
const uint8_t *get_string(rbuf *r, uint32_t *n); /* zero-copy view */
int get_cstring(rbuf *r, char *out, size_t cap); /* NUL-terminated copy */

uint32_t peek_u32(const uint8_t *p);
void poke_u32(uint8_t *p, uint32_t v);

#endif
