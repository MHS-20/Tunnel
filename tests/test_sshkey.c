/* ssh-ed25519: key files written by ssh-keygen, signatures, known_hosts.
 * Key material is the RFC 8032 section 7.1 TEST 1 vector, packed into
 * the OpenSSH private key format by tests/fixtures. */
#include <sodium.h>
#include <stdlib.h>
#include <unistd.h>

#include "authkeys.h"
#include "check.h"
#include "knownhosts.h"
#include "sshkey.h"

int main(int argc, char **argv)
{
	if (sodium_init() < 0)
		return 1;
	const char *dir = argc > 1 ? argv[1] : "tests/fixtures";
	char path[512];
	ed25519_key k;
	uint8_t pk[32], want_pk[32], want_sig[64];
	unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", want_pk);
	unhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
	      "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", want_sig);

	snprintf(path, sizeof path, "%s/rfc8032_ed25519", dir);
	CHECK(sshkey_load_private(path, &k) == 0);
	CHECK_MEM(k.pk, want_pk, 32);

	/* RFC 8032 TEST 1: empty message. */
	wbuf sig;
	wbuf_init(&sig);
	sshkey_sign(&k, (const uint8_t *)"", 0, &sig);
	CHECK(sig.len == 4 + 11 + 4 + 64);
	CHECK_MEM(sig.data + sig.len - 64, want_sig, 64);
	CHECK(sshkey_verify(k.pk, (const uint8_t *)"", 0, sig.data, sig.len) == 0);
	CHECK(sshkey_verify(k.pk, (const uint8_t *)"x", 1, sig.data, sig.len) == -1);

	/* Public key line produced by ssh-keygen -y matches. */
	char line[512];
	snprintf(path, sizeof path, "%s/rfc8032_ed25519.pub", dir);
	FILE *f = fopen(path, "r");
	CHECK(f && fgets(line, sizeof line, f));
	if (f)
		fclose(f);
	CHECK(sshkey_parse_publine(line, pk) == 0);
	CHECK_MEM(pk, want_pk, 32);
	char fmt[SSHKEY_PUBLINE_MAX];
	sshkey_format_publine(pk, fmt, sizeof fmt);
	CHECK(strncmp(line, fmt, strlen(fmt)) == 0);
	CHECK(sshkey_parse_publine("ssh-rsa AAAAB3NzaC1yc2E= x", pk) == -1);
	CHECK(authkeys_allowed(path, want_pk));

	/* known_hosts: unknown, add, match, mismatch on another key. */
	char kh[] = "/tmp/tunnel-kh-XXXXXX";
	int fd = mkstemp(kh);
	close(fd);
	CHECK(knownhosts_check(kh, "127.0.0.1", 2222, want_pk) == KH_UNKNOWN);
	CHECK(knownhosts_add(kh, "127.0.0.1", 2222, want_pk) == 0);
	CHECK(knownhosts_check(kh, "127.0.0.1", 2222, want_pk) == KH_MATCH);
	CHECK(knownhosts_check(kh, "127.0.0.1", 22, want_pk) == KH_UNKNOWN);
	uint8_t other[32] = {1};
	CHECK(knownhosts_check(kh, "127.0.0.1", 2222, other) == KH_MISMATCH);
	unlink(kh);
	wbuf_free(&sig);
	return check_report("test_sshkey");
}
