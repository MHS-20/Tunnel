/* KEXINIT encoding and RFC 4253 section 7.1 negotiation. */
#include <stdlib.h>

#include "check.h"
#include "kexinit.h"

static const char *const client_lists[KI_NLISTS] = {
	"sntrup761x25519-sha512,curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com",
	"ssh-ed25519,rsa-sha2-512",
	"chacha20-poly1305@openssh.com,aes128-ctr",
	"aes128-ctr,chacha20-poly1305@openssh.com",
	"hmac-sha2-256", "hmac-sha2-256",
	"none,zlib@openssh.com", "none",
	"", "",
};

static const char *const server_lists[KI_NLISTS] = {
	"curve25519-sha256,curve25519-sha256@libssh.org,kex-strict-s-v00@openssh.com",
	"ssh-ed25519",
	"chacha20-poly1305@openssh.com", "chacha20-poly1305@openssh.com",
	"none", "none", "none", "none", "", "",
};

int main(void)
{
	char out[ALG_NAME_MAX];
	CHECK(namelist_choose("a,b,c", "c,b", out, sizeof out) == 0 && !strcmp(out, "b"));
	CHECK(namelist_choose("a,b", "c,d", out, sizeof out) == -1);
	CHECK(namelist_choose("", "a", out, sizeof out) == -1);
	CHECK(namelist_choose("ab,a", "a", out, sizeof out) == 0 && !strcmp(out, "a"));
	CHECK(namelist_contains("x,kex-strict-c-v00@openssh.com", "kex-strict-c-v00@openssh.com"));
	CHECK(!namelist_contains("abc", "ab"));

	kexinit c, s, d;
	CHECK(kexinit_new(&c, client_lists) == 0);
	CHECK(kexinit_new(&s, server_lists) == 0);

	/* Encode/decode round trip. */
	wbuf w;
	wbuf_init(&w);
	kexinit_encode(&c, &w);
	CHECK(!w.err && w.data[0] == 20);
	CHECK(kexinit_decode(w.data, w.len, &d) == 0);
	CHECK_MEM(d.cookie, c.cookie, 16);
	for (int i = 0; i < KI_NLISTS; i++)
		CHECK(!strcmp(d.lists[i], client_lists[i]));
	CHECK(kexinit_decode(w.data, w.len - 1, &d) == -1); /* truncated */
	kexinit_free(&d);
	wbuf_free(&w);

	/* Client preference wins; enc directions negotiate independently. */
	kex_algs a;
	CHECK(kexinit_negotiate(&c, &s, &a) == 0);
	CHECK(!strcmp(a.kex, "curve25519-sha256"));
	CHECK(!strcmp(a.hostkey, "ssh-ed25519"));
	CHECK(!strcmp(a.enc_cs, "chacha20-poly1305@openssh.com"));
	CHECK(!strcmp(a.enc_sc, "chacha20-poly1305@openssh.com"));
	CHECK(!strcmp(a.comp_cs, "none") && a.mac_cs[0] == 0);
	CHECK(!a.guess_wrong);

	/* A wrong guess is detected when the first kex entries differ. */
	c.first_kex_follows = 1;
	CHECK(kexinit_negotiate(&c, &s, &a) == 0 && a.guess_wrong);

	/* No common cipher means failure. */
	free(s.lists[KI_ENC_SC]);
	s.lists[KI_ENC_SC] = strdup("aes256-gcm@openssh.com");
	CHECK(kexinit_negotiate(&c, &s, &a) == -1);

	kexinit_free(&c);
	kexinit_free(&s);
	return check_report("test_kexinit");
}
