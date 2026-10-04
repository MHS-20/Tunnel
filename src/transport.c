#include "transport.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

#include "kdf.h"
#include "kex.h"
#include "kexinit.h"
#include "ssh_msg.h"

static const char *const client_algs[KI_NLISTS] = {
	KEX_CURVE25519 "," KEX_CURVE25519_LIBSSH "," KEX_STRICT_C,
	SSHKEY_ED25519,
	CIPHER_CHACHAPOLY_NAME, CIPHER_CHACHAPOLY_NAME,
	"none", "none", /* MAC: unused with an AEAD cipher */
	"none", "none",
	"", "",
};

static const char *const server_algs[KI_NLISTS] = {
	KEX_CURVE25519 "," KEX_CURVE25519_LIBSSH "," KEX_STRICT_S,
	SSHKEY_ED25519,
	CIPHER_CHACHAPOLY_NAME, CIPHER_CHACHAPOLY_NAME,
	"none", "none",
	"none", "none",
	"", "",
};

/* State of one key exchange, from KEXINIT to NEWKEYS. */
typedef struct {
	wbuf i_c, i_s;           /* KEXINIT payloads, for H */
	kexinit peer;
	kex_algs algs;
	wbuf k;                  /* shared secret mpint */
	uint8_t H[32];
	uint8_t q_c[32], q_s[32];
	uint8_t eph_priv[32];
} kex_state;

static void kex_state_free(kex_state *ks)
{
	wbuf_free(&ks->i_c);
	wbuf_free(&ks->i_s);
	wbuf_free(&ks->k);
	kexinit_free(&ks->peer);
	sodium_memzero(ks, sizeof *ks);
}

int tr_send(transport *tr, const wbuf *payload)
{
	if (payload->err)
		return -1;
	return pkt_send(&tr->pc, payload->data, payload->len);
}

static int send_byte(transport *tr, uint8_t msg)
{
	return pkt_send(&tr->pc, &msg, 1);
}

void tr_disconnect(transport *tr, uint32_t reason, const char *desc)
{
	wbuf w;
	wbuf_init(&w);
	put_u8(&w, SSH_MSG_DISCONNECT);
	put_u32(&w, reason);
	put_cstring(&w, desc);
	put_cstring(&w, "");
	tr_send(tr, &w);
	wbuf_free(&w);
}

void tr_unimplemented(transport *tr)
{
	wbuf w;
	wbuf_init(&w);
	put_u8(&w, SSH_MSG_UNIMPLEMENTED);
	put_u32(&w, tr->pc.rx.seq - 1);
	tr_send(tr, &w);
	wbuf_free(&w);
}

static void report_disconnect(const wbuf *m)
{
	rbuf r;
	char desc[256];
	rbuf_init(&r, m->data + 1, m->len - 1);
	uint32_t reason = get_u32(&r);
	get_cstring(&r, desc, sizeof desc);
	fprintf(stderr, "tunnel: peer disconnected (%u): %s\n", reason, r.err ? "?" : desc);
}

/* Reads the next key exchange message. During the initial exchange under
 * strict KEX any other message is fatal; otherwise IGNORE/DEBUG pass. */
static int recv_kex_msg(transport *tr, wbuf *m, uint8_t expected)
{
	for (;;) {
		if (pkt_recv(&tr->pc, m) < 0 || m->len == 0)
			return -1;
		uint8_t t = m->data[0];
		if (t == expected)
			return 0;
		if (t == SSH_MSG_DISCONNECT) {
			report_disconnect(m);
			return -1;
		}
		int initial_strict = tr->strict && !tr->have_session_id;
		if (!initial_strict && (t == SSH_MSG_IGNORE || t == SSH_MSG_DEBUG))
			continue;
		fprintf(stderr, "tunnel: unexpected message %u during kex (want %u)\n", t, expected);
		return -1;
	}
}

static int install_keys(transport *tr, kex_state *ks, pkt_dir *dir, const char *alg, char letter)
{
	cipher_kind kind;
	uint8_t key[CIPHER_KEY_MAX];
	if (cipher_by_name(alg, &kind) < 0)
		return -1;
	kdf_derive(ks->k.data, ks->k.len, ks->H, letter, tr->session_id, key, cipher_key_len(kind));
	cipher_init(&dir->ctx, kind, key);
	sodium_memzero(key, sizeof key);
	if (tr->strict)
		dir->seq = 0;
	return 0;
}

static void compute_hash(transport *tr, kex_state *ks, const uint8_t *k_s, size_t k_s_len)
{
	kex_hash_input in = {
		.v_c = tr->v_c, .v_s = tr->v_s,
		.i_c = &ks->i_c, .i_s = &ks->i_s,
		.k_s = k_s, .k_s_len = k_s_len,
		.q_c = ks->q_c, .q_s = ks->q_s, .k = &ks->k,
	};
	kex_exchange_hash(&in, ks->H);
	if (!tr->have_session_id) {
		memcpy(tr->session_id, ks->H, 32);
		tr->have_session_id = 1;
	}
}

/* Client: send Q_C, receive K_S || Q_S || signature, verify. */
static int ecdh_client(transport *tr, kex_state *ks)
{
	wbuf m;
	rbuf r;
	uint32_t kn, qn, sn;
	uint8_t pk[32];
	int rc = -1;

	wbuf_init(&m);
	kex_c25519_keygen(ks->q_c, ks->eph_priv);
	put_u8(&m, SSH_MSG_KEX_ECDH_INIT);
	put_string(&m, ks->q_c, 32);
	if (tr_send(tr, &m) < 0 || recv_kex_msg(tr, &m, SSH_MSG_KEX_ECDH_REPLY) < 0)
		goto out;
	rbuf_init(&r, m.data + 1, m.len - 1);
	const uint8_t *k_s = get_string(&r, &kn);
	const uint8_t *q_s = get_string(&r, &qn);
	const uint8_t *sig = get_string(&r, &sn);
	if (r.err || qn != 32 || sshkey_parse_blob(k_s, kn, pk) < 0)
		goto out;
	memcpy(ks->q_s, q_s, 32);
	if (kex_c25519_shared(&ks->k, ks->eph_priv, ks->q_s) < 0)
		goto out;
	compute_hash(tr, ks, k_s, kn);
	if (sshkey_verify(pk, ks->H, 32, sig, sn) < 0) {
		fprintf(stderr, "tunnel: host key signature verification failed\n");
		goto out;
	}
	if (tr->check_hostkey(pk, tr->check_arg) < 0) {
		tr_disconnect(tr, SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE, "host key rejected");
		goto out;
	}
	rc = 0;
out:
	wbuf_free(&m);
	return rc;
}

/* Server: receive Q_C, reply with K_S || Q_S || signature over H. */
static int ecdh_server(transport *tr, kex_state *ks)
{
	wbuf m, k_s, sig;
	rbuf r;
	uint32_t qn;
	int rc = -1;

	wbuf_init(&m);
	wbuf_init(&k_s);
	wbuf_init(&sig);
	if (recv_kex_msg(tr, &m, SSH_MSG_KEX_ECDH_INIT) < 0)
		goto out;
	rbuf_init(&r, m.data + 1, m.len - 1);
	const uint8_t *q_c = get_string(&r, &qn);
	if (r.err || qn != 32)
		goto out;
	memcpy(ks->q_c, q_c, 32);
	kex_c25519_keygen(ks->q_s, ks->eph_priv);
	if (kex_c25519_shared(&ks->k, ks->eph_priv, ks->q_c) < 0)
		goto out;
	sshkey_put_blob(&k_s, tr->hostkey->pk);
	compute_hash(tr, ks, k_s.data, k_s.len);
	sshkey_sign(tr->hostkey, ks->H, 32, &sig);

	wbuf_reset(&m);
	put_u8(&m, SSH_MSG_KEX_ECDH_REPLY);
	put_string(&m, k_s.data, k_s.len);
	put_string(&m, ks->q_s, 32);
	put_string(&m, sig.data, sig.len);
	rc = tr_send(tr, &m);
out:
	wbuf_free(&m);
	wbuf_free(&k_s);
	wbuf_free(&sig);
	return rc;
}

/* One complete key exchange. peer_kexinit is the peer's KEXINIT if it
 * already arrived (peer-initiated re-exchange), else NULL. */
static int kex_run(transport *tr, const wbuf *peer_kexinit)
{
	kex_state ks;
	kexinit mine;
	wbuf peer_raw;
	int rc = -1;

	memset(&ks, 0, sizeof ks);
	wbuf_init(&peer_raw);
	if (kexinit_new(&mine, tr->is_server ? server_algs : client_algs) < 0)
		return -1;
	wbuf *own = tr->is_server ? &ks.i_s : &ks.i_c;
	wbuf *theirs = tr->is_server ? &ks.i_c : &ks.i_s;
	kexinit_encode(&mine, own);
	if (tr_send(tr, own) < 0)
		goto out;

	if (peer_kexinit)
		put_raw(theirs, peer_kexinit->data, peer_kexinit->len);
	else if (recv_kex_msg(tr, &peer_raw, SSH_MSG_KEXINIT) == 0)
		put_raw(theirs, peer_raw.data, peer_raw.len);
	else
		goto out;
	if (theirs->err || kexinit_decode(theirs->data, theirs->len, &ks.peer) < 0)
		goto out;

	const kexinit *c = tr->is_server ? &ks.peer : &mine;
	const kexinit *s = tr->is_server ? &mine : &ks.peer;
	if (kexinit_negotiate(c, s, &ks.algs) < 0) {
		tr_disconnect(tr, SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "no matching algorithms");
		goto out;
	}
	if (!tr->have_session_id)
		tr->strict = tr->is_server ? namelist_contains(c->lists[KI_KEX], KEX_STRICT_C)
					   : namelist_contains(s->lists[KI_KEX], KEX_STRICT_S);
	if (ks.algs.guess_wrong && ks.peer.first_kex_follows &&
	    pkt_recv(&tr->pc, &peer_raw) < 0) /* discard the wrong guess */
		goto out;

	if ((tr->is_server ? ecdh_server : ecdh_client)(tr, &ks) < 0)
		goto out;

	const char *tx_alg = tr->is_server ? ks.algs.enc_sc : ks.algs.enc_cs;
	const char *rx_alg = tr->is_server ? ks.algs.enc_cs : ks.algs.enc_sc;
	if (send_byte(tr, SSH_MSG_NEWKEYS) < 0 ||
	    install_keys(tr, &ks, &tr->pc.tx, tx_alg, tr->is_server ? 'D' : 'C') < 0)
		goto out;
	if (recv_kex_msg(tr, &peer_raw, SSH_MSG_NEWKEYS) < 0 ||
	    install_keys(tr, &ks, &tr->pc.rx, rx_alg, tr->is_server ? 'C' : 'D') < 0)
		goto out;
	rc = 0;
out:
	kexinit_free(&mine);
	wbuf_free(&peer_raw);
	kex_state_free(&ks);
	return rc;
}

static int start(transport *tr, int fd)
{
	char *mine = tr->is_server ? tr->v_s : tr->v_c;
	char *theirs = tr->is_server ? tr->v_c : tr->v_s;
	pkt_init(&tr->pc, fd);
	strcpy(mine, TUNNEL_IDENT);
	if (version_send(fd, mine) < 0 || version_recv(fd, theirs, VERSION_MAX + 1) < 0) {
		fprintf(stderr, "tunnel: version exchange failed\n");
		return -1;
	}
	return kex_run(tr, NULL);
}

int tr_client_start(transport *tr, int fd, hostkey_check_fn check, void *arg)
{
	memset(tr, 0, sizeof *tr);
	tr->check_hostkey = check;
	tr->check_arg = arg;
	return start(tr, fd);
}

int tr_server_start(transport *tr, int fd, const ed25519_key *hostkey)
{
	memset(tr, 0, sizeof *tr);
	tr->is_server = 1;
	tr->hostkey = hostkey;
	return start(tr, fd);
}

int tr_recv(transport *tr, wbuf *m)
{
	for (;;) {
		if (pkt_recv(&tr->pc, m) < 0 || m->len == 0)
			return -1;
		switch (m->data[0]) {
		case SSH_MSG_IGNORE:
		case SSH_MSG_DEBUG:
		case SSH_MSG_UNIMPLEMENTED:
		case SSH_MSG_EXT_INFO:
			continue;
		case SSH_MSG_DISCONNECT:
			report_disconnect(m);
			return -1;
		case SSH_MSG_KEXINIT:
			/* Peer-initiated re-exchange (RFC 4253 section 9). We run it
			 * to completion before returning, so no upper-layer message
			 * is sent while it is in progress. */
			if (kex_run(tr, m) < 0)
				return -1;
			continue;
		default:
			return 0;
		}
	}
}
