#include "sshkey.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

#define PEM_BEGIN "-----BEGIN OPENSSH PRIVATE KEY-----"
#define PEM_END "-----END OPENSSH PRIVATE KEY-----"
#define KEY_MAGIC "openssh-key-v1"

void sshkey_put_blob(wbuf *w, const uint8_t pk[32])
{
	put_cstring(w, SSHKEY_ED25519);
	put_string(w, pk, 32);
}

static int string_equals(const uint8_t *p, uint32_t n, const char *s)
{
	return p && n == strlen(s) && memcmp(p, s, n) == 0;
}

int sshkey_parse_blob(const uint8_t *p, size_t n, uint8_t pk[32])
{
	rbuf r;
	uint32_t tn, kn;
	rbuf_init(&r, p, n);
	const uint8_t *type = get_string(&r, &tn);
	const uint8_t *key = get_string(&r, &kn);
	if (r.err || rbuf_left(&r) || !string_equals(type, tn, SSHKEY_ED25519) || kn != 32)
		return -1;
	memcpy(pk, key, 32);
	return 0;
}

void sshkey_sign(const ed25519_key *k, const uint8_t *m, size_t n, wbuf *sig)
{
	uint8_t s[crypto_sign_BYTES];
	crypto_sign_detached(s, NULL, m, n, k->sk);
	put_cstring(sig, SSHKEY_ED25519);
	put_string(sig, s, sizeof s);
}

int sshkey_verify(const uint8_t pk[32], const uint8_t *m, size_t n,
		  const uint8_t *sig, size_t sig_len)
{
	rbuf r;
	uint32_t tn, sn;
	rbuf_init(&r, sig, sig_len);
	const uint8_t *type = get_string(&r, &tn);
	const uint8_t *s = get_string(&r, &sn);
	if (r.err || rbuf_left(&r) || !string_equals(type, tn, SSHKEY_ED25519) ||
	    sn != crypto_sign_BYTES)
		return -1;
	return crypto_sign_verify_detached(s, m, n, pk) == 0 ? 0 : -1;
}

/* Strips the PEM armour and base64-decodes the body into out. */
static int pem_decode(const char *text, uint8_t *out, size_t cap, size_t *n)
{
	const char *b = strstr(text, PEM_BEGIN), *e = strstr(text, PEM_END);
	if (!b || !e || e < b)
		return -1;
	b += strlen(PEM_BEGIN);
	return sodium_base642bin(out, cap, b, (size_t)(e - b), " \t\r\n", n, NULL,
				 sodium_base64_VARIANT_ORIGINAL);
}

/* PROTOCOL.key: magic, cipher "none", kdf "none", kdfoptions, nkeys=1,
 * public blob, then the private section:
 *   uint32 check, uint32 check, string type, string pk, string sk(64),
 *   string comment, padding 1,2,3... */
static int parse_openssh_key(const uint8_t *p, size_t n, ed25519_key *k)
{
	rbuf r, priv;
	uint32_t len, sn, pn, skn, tn;
	if (n < sizeof KEY_MAGIC || memcmp(p, KEY_MAGIC, sizeof KEY_MAGIC) != 0)
		return -1;
	rbuf_init(&r, p + sizeof KEY_MAGIC, n - sizeof KEY_MAGIC);
	const uint8_t *cipher = get_string(&r, &len);
	if (!string_equals(cipher, len, "none"))
		return -1; /* passphrase-protected keys are not supported */
	get_string(&r, &len); /* kdfname */
	get_string(&r, &len); /* kdfoptions */
	if (get_u32(&r) != 1)
		return -1;
	get_string(&r, &len); /* public blob, repeated in the private part */
	const uint8_t *section = get_string(&r, &sn);
	if (r.err)
		return -1;

	rbuf_init(&priv, section, sn);
	if (get_u32(&priv) != get_u32(&priv))
		return -1;
	const uint8_t *type = get_string(&priv, &tn);
	const uint8_t *pk = get_string(&priv, &pn);
	const uint8_t *sk = get_string(&priv, &skn);
	if (priv.err || !string_equals(type, tn, SSHKEY_ED25519) || pn != 32 || skn != 64 ||
	    memcmp(sk + 32, pk, 32) != 0)
		return -1;
	memcpy(k->pk, pk, 32);
	memcpy(k->sk, sk, 64);
	return 0;
}

int sshkey_load_private(const char *path, ed25519_key *k)
{
	char text[8192];
	uint8_t raw[8192];
	size_t n;
	FILE *f = fopen(path, "r");
	if (!f)
		return -1;
	size_t tl = fread(text, 1, sizeof text - 1, f);
	fclose(f);
	text[tl] = 0;
	int rc = pem_decode(text, raw, sizeof raw, &n) == 0 ? parse_openssh_key(raw, n, k) : -1;
	sodium_memzero(text, sizeof text);
	sodium_memzero(raw, sizeof raw);
	return rc;
}

int sshkey_parse_publine(const char *line, uint8_t pk[32])
{
	uint8_t blob[256];
	size_t n;
	const char *end;
	line += strspn(line, " \t");
	size_t tl = strcspn(line, " \t");
	if (tl != strlen(SSHKEY_ED25519) || strncmp(line, SSHKEY_ED25519, tl) != 0)
		return -1;
	line += tl;
	line += strspn(line, " \t");
	if (sodium_base642bin(blob, sizeof blob, line, strcspn(line, " \t\r\n"), NULL, &n, &end,
			      sodium_base64_VARIANT_ORIGINAL) != 0)
		return -1;
	return sshkey_parse_blob(blob, n, pk);
}

void sshkey_format_publine(const uint8_t pk[32], char *out, size_t cap)
{
	wbuf w;
	char b64[sodium_base64_ENCODED_LEN(64, sodium_base64_VARIANT_ORIGINAL)];
	wbuf_init(&w);
	sshkey_put_blob(&w, pk);
	sodium_bin2base64(b64, sizeof b64, w.data, w.len, sodium_base64_VARIANT_ORIGINAL);
	snprintf(out, cap, "%s %s", SSHKEY_ED25519, b64);
	wbuf_free(&w);
}

void sshkey_fingerprint(const uint8_t pk[32], char *out, size_t cap)
{
	wbuf w;
	uint8_t h[32];
	char b64[sodium_base64_ENCODED_LEN(32, sodium_base64_VARIANT_ORIGINAL_NO_PADDING)];
	wbuf_init(&w);
	sshkey_put_blob(&w, pk);
	crypto_hash_sha256(h, w.data, w.len);
	sodium_bin2base64(b64, sizeof b64, h, sizeof h, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
	snprintf(out, cap, "SHA256:%s", b64);
	wbuf_free(&w);
}
