#include <sodium.h>
#include <stdio.h>
#include <string.h>

#include "authkeys.h"
#include "ssh_msg.h"
#include "userauth.h"

#define MAX_ATTEMPTS 20

static int accept_service(transport *tr)
{
	wbuf m;
	char name[64];
	int rc = -1;
	wbuf_init(&m);
	if (tr_recv(tr, &m) == 0 && m.data[0] == SSH_MSG_SERVICE_REQUEST) {
		rbuf r;
		rbuf_init(&r, m.data + 1, m.len - 1);
		if (get_cstring(&r, name, sizeof name) == 0 && !strcmp(name, USERAUTH_SERVICE)) {
			wbuf_reset(&m);
			put_u8(&m, SSH_MSG_SERVICE_ACCEPT);
			put_cstring(&m, USERAUTH_SERVICE);
			rc = tr_send(tr, &m);
		} else {
			tr_disconnect(tr, SSH_DISCONNECT_SERVICE_NOT_AVAILABLE, "unknown service");
		}
	}
	wbuf_free(&m);
	return rc;
}

static int send_failure(transport *tr, const auth_server_cfg *cfg)
{
	wbuf m;
	wbuf_init(&m);
	put_u8(&m, SSH_MSG_USERAUTH_FAILURE);
	if (cfg->authorized_keys && cfg->password)
		put_cstring(&m, "publickey,password");
	else
		put_cstring(&m, cfg->authorized_keys ? "publickey" : cfg->password ? "password" : "");
	put_bool(&m, 0); /* partial success */
	int rc = tr_send(tr, &m);
	wbuf_free(&m);
	return rc;
}

/* 1 authenticated, 0 rejected, 2 PK_OK sent (client will follow up), -1 error. */
static int try_publickey(transport *tr, const auth_server_cfg *cfg, rbuf *r, const wbuf *msg)
{
	uint32_t an, bn, sn;
	uint8_t pk[32];
	int has_sig = get_bool(r);
	const uint8_t *alg = get_string(r, &an);
	const uint8_t *blob = get_string(r, &bn);
	if (r->err || !cfg->authorized_keys || an != strlen(SSHKEY_ED25519) ||
	    memcmp(alg, SSHKEY_ED25519, an) != 0 || sshkey_parse_blob(blob, bn, pk) < 0 ||
	    !authkeys_allowed(cfg->authorized_keys, pk))
		return 0;

	if (!has_sig) { /* query: "would this key be acceptable?" */
		wbuf ok;
		wbuf_init(&ok);
		put_u8(&ok, SSH_MSG_USERAUTH_PK_OK);
		put_string(&ok, alg, an);
		put_string(&ok, blob, bn);
		int rc = tr_send(tr, &ok);
		wbuf_free(&ok);
		return rc < 0 ? -1 : 2;
	}

	size_t signed_len = r->off; /* request bytes before the signature */
	const uint8_t *sig = get_string(r, &sn);
	if (r->err)
		return 0;
	wbuf data;
	wbuf_init(&data);
	put_string(&data, tr->session_id, sizeof tr->session_id);
	put_raw(&data, msg->data, signed_len);
	int ok = sshkey_verify(pk, data.data, data.len, sig, sn) == 0;
	wbuf_free(&data);
	return ok;
}

static int try_password(const auth_server_cfg *cfg, rbuf *r)
{
	uint32_t n;
	uint8_t a[32], b[32];
	int change = get_bool(r);
	const uint8_t *pw = get_string(r, &n);
	if (r->err || change || !cfg->password)
		return 0;
	/* Compare digests so the comparison is constant-time and
	 * length-independent. */
	crypto_hash_sha256(a, pw, n);
	crypto_hash_sha256(b, (const uint8_t *)cfg->password, strlen(cfg->password));
	return sodium_memcmp(a, b, sizeof a) == 0;
}

int userauth_server(transport *tr, const auth_server_cfg *cfg)
{
	wbuf m;
	int rc = -1;
	if (accept_service(tr) < 0)
		return -1;
	wbuf_init(&m);
	for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
		char user[256], service[64], method[64];
		rbuf r;
		if (tr_recv(tr, &m) < 0)
			break;
		if (m.data[0] != SSH_MSG_USERAUTH_REQUEST) {
			tr_unimplemented(tr);
			continue;
		}
		rbuf_init(&r, m.data, m.len);
		get_u8(&r);
		get_cstring(&r, user, sizeof user);
		get_cstring(&r, service, sizeof service);
		get_cstring(&r, method, sizeof method);
		int ok = 0;
		if (!r.err && !strcmp(user, cfg->user) && !strcmp(service, CONNECTION_SERVICE)) {
			if (!strcmp(method, "publickey"))
				ok = try_publickey(tr, cfg, &r, &m);
			else if (!strcmp(method, "password"))
				ok = try_password(cfg, &r);
		}
		if (ok < 0)
			break;
		if (ok == 2)
			continue; /* PK_OK sent */
		if (ok == 1) {
			wbuf_reset(&m);
			put_u8(&m, SSH_MSG_USERAUTH_SUCCESS);
			rc = tr_send(tr, &m);
			break;
		}
		if (send_failure(tr, cfg) < 0)
			break;
	}
	if (rc < 0)
		tr_disconnect(tr, SSH_DISCONNECT_NO_MORE_AUTH_METHODS, "authentication failed");
	wbuf_free(&m);
	return rc;
}
