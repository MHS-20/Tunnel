/* curve25519 (RFC 7748 vectors) and RFC 4253 7.2 key derivation. */
#include <sodium.h>

#include "check.h"
#include "kdf.h"
#include "kex.h"

int main(void)
{
	if (sodium_init() < 0)
		return 1;
	uint8_t a_priv[32], a_pub[32], b_priv[32], b_pub[32], want[128], pub[32];
	unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a_priv);
	unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", a_pub);
	unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", b_priv);
	unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", b_pub);
	crypto_scalarmult_base(pub, a_priv);
	CHECK_MEM(pub, a_pub, 32);

	wbuf ka, kb;
	wbuf_init(&ka);
	wbuf_init(&kb);
	CHECK(kex_c25519_shared(&ka, a_priv, b_pub) == 0);
	CHECK(kex_c25519_shared(&kb, b_priv, a_pub) == 0);
	size_t n = unhex("00000020"
			 "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", want);
	CHECK(ka.len == n && kb.len == n);
	CHECK_MEM(ka.data, want, n);
	CHECK_MEM(kb.data, want, n);

	/* Low-order point (all zero) must be rejected. */
	uint8_t zero[32] = {0};
	wbuf_reset(&ka);
	CHECK(kex_c25519_shared(&ka, a_priv, zero) == -1);

	/* KDF: three hash blocks, checked against an independent Python
	 * hashlib computation (see DESIGN.md). K has a leading 0x00 pad. */
	uint8_t k[64], H[32], sid[32], out[80];
	size_t kn = unhex("0000002100f0"
			  "11111111111111111111111111111111111111111111111111111111111111", k);
	for (int i = 0; i < 32; i++) {
		H[i] = (uint8_t)i;
		sid[i] = (uint8_t)(32 + i);
	}
	kdf_derive(k, kn, H, 'C', sid, out, sizeof out);
	unhex("af5a8673b7d63867118e79a714d0c5a7d5d4b32e4ba9c2a8b032c59cc1ab5939"
	      "b4649b8c18de34322ab5c2afc8213070974341083c840cecb4c2e5540135acab"
	      "6a628dd6505edccf1af1d219123cfa66", want);
	CHECK(kn == 37);
	CHECK_MEM(out, want, 80);
	/* Shorter outputs are prefixes. */
	uint8_t shorter[20];
	kdf_derive(k, kn, H, 'C', sid, shorter, sizeof shorter);
	CHECK_MEM(shorter, want, 20);
	wbuf_free(&ka);
	wbuf_free(&kb);
	return check_report("test_kex");
}
