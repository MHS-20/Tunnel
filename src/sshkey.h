/* ssh-ed25519 keys (RFC 8709): public key blobs, signatures, the
 * OpenSSH private key file format (PROTOCOL.key, unencrypted only) and
 * one-line public key text ("ssh-ed25519 AAAA... comment"). */
#ifndef TUNNEL_SSHKEY_H
#define TUNNEL_SSHKEY_H

#include <stddef.h>
#include <stdint.h>

#include "buf.h"

#define SSHKEY_ED25519 "ssh-ed25519"
#define SSHKEY_PUBLINE_MAX 128

typedef struct {
	uint8_t pk[32];
	uint8_t sk[64]; /* seed || pk, libsodium layout */
} ed25519_key;

int sshkey_load_private(const char *path, ed25519_key *k);

/* string "ssh-ed25519" || string pk */
void sshkey_put_blob(wbuf *w, const uint8_t pk[32]);
int sshkey_parse_blob(const uint8_t *p, size_t n, uint8_t pk[32]);

/* string "ssh-ed25519" || string signature(64) */
void sshkey_sign(const ed25519_key *k, const uint8_t *m, size_t n, wbuf *sig);
int sshkey_verify(const uint8_t pk[32], const uint8_t *m, size_t n,
		  const uint8_t *sig, size_t sig_len);

/* Parses "ssh-ed25519 <base64 blob> [comment]"; -1 for other key types. */
int sshkey_parse_publine(const char *line, uint8_t pk[32]);
void sshkey_format_publine(const uint8_t pk[32], char *out, size_t cap);
void sshkey_fingerprint(const uint8_t pk[32], char *out, size_t cap); /* SHA256:... */

#endif
