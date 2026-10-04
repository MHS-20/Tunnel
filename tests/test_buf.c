/* Wire encoding: RFC 4251 section 5, including its mpint examples. */
#include "buf.h"
#include "check.h"

static void mpint_case(const char *mag_hex, const char *want_hex)
{
	unsigned char mag[64], want[64];
	size_t mn = unhex(mag_hex, mag), wn = unhex(want_hex, want);
	wbuf w;
	wbuf_init(&w);
	put_mpint(&w, mag, mn);
	CHECK(!w.err && w.len == wn);
	CHECK_MEM(w.data, want, wn);
	wbuf_free(&w);
}

int main(void)
{
	/* RFC 4251 section 5 examples (non-negative ones). */
	mpint_case("", "00000000");
	mpint_case("00", "00000000");
	mpint_case("09a378f9b2e332a7", "0000000809a378f9b2e332a7");
	mpint_case("80", "000000020080");
	mpint_case("0000ff", "0000000200ff");

	wbuf w;
	wbuf_init(&w);
	put_u8(&w, 7);
	put_u32(&w, 0xdeadbeef);
	put_bool(&w, 5);
	put_cstring(&w, "testing");
	put_cstring(&w, "zlib,none");
	put_string(&w, "", 0);
	CHECK(!w.err);
	unsigned char want[64];
	size_t wn = unhex("07deadbeef01"
			  "0000000774657374696e67"
			  "000000097a6c69622c6e6f6e65"
			  "00000000", want);
	CHECK(w.len == wn);
	CHECK_MEM(w.data, want, wn);

	rbuf r;
	char s[16];
	rbuf_init(&r, w.data, w.len);
	CHECK(get_u8(&r) == 7);
	CHECK(get_u32(&r) == 0xdeadbeef);
	CHECK(get_bool(&r) == 1);
	CHECK(get_cstring(&r, s, sizeof s) == 0 && strcmp(s, "testing") == 0);
	CHECK(get_cstring(&r, s, 5) == -1 && r.err); /* too long for out */
	wbuf_free(&w);

	/* Bounds: a string length past the end is an error, not a read. */
	unsigned char bad[] = {0, 0, 0, 9, 'a', 'b'};
	uint32_t n;
	rbuf_init(&r, bad, sizeof bad);
	CHECK(get_string(&r, &n) == NULL && r.err && n == 0);
	CHECK(get_u32(&r) == 0 && r.err); /* errors are sticky */

	/* Embedded NUL rejected for C strings. */
	unsigned char nul[] = {0, 0, 0, 2, 'a', 0};
	rbuf_init(&r, nul, sizeof nul);
	CHECK(get_cstring(&r, s, sizeof s) == -1);

	/* Writer bound. */
	wbuf_init(&w);
	CHECK(wbuf_reserve(&w, BUF_MAX + 1) == NULL && w.err);
	put_u8(&w, 1);
	CHECK(w.len == 0);
	wbuf_free(&w);
	return check_report("test_buf");
}
