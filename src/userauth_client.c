#include <stdio.h>
#include <string.h>

#include "kexinit.h"
#include "ssh_msg.h"
#include "userauth.h"

static void put_request_head(wbuf *w, const char *user, const char *method)
{
	put_u8(w, SSH_MSG_USERAUTH_REQUEST);
	put_cstring(w, user);
	put_cstring(w, CONNECTION_SERVICE);
	put_cstring(w, method);
}

static void print_banner(const wbuf *m)
{
	rbuf r;
	uint32_t n;
	rbuf_init(&r, m->data + 1, m->len - 1);
	const uint8_t *msg = get_string(&r, &n);
	if (msg)
		fprintf(stderr, "%.*s", (int)n, (const char *)msg);
}

/* Waits for the outcome of one request: 1 success, 0 failure (methods
 * that can continue are copied out), -1 error. */
static int await_result(transport *tr, char *methods, size_t cap)
{
	wbuf m;
	int rc = -1;
	wbuf_init(&m);
	while (tr_recv(tr, &m) == 0) {
		if (m.data[0] == SSH_MSG_USERAUTH_BANNER) {
			print_banner(&m);
			continue;
		}
		if (m.data[0] == SSH_MSG_USERAUTH_SUCCESS) {
			rc = 1;
		} else if (m.data[0] == SSH_MSG_USERAUTH_FAILURE) {
			rbuf r;
			rbuf_init(&r, m.data + 1, m.len - 1);
			rc = get_cstring(&r, methods, cap) == 0 ? 0 : -1;
		}
		break;
	}
	wbuf_free(&m);
	return rc;
}

static int request_service(transport *tr)
{
	wbuf m;
	char name[64];
	int rc = -1;
	wbuf_init(&m);
	put_u8(&m, SSH_MSG_SERVICE_REQUEST);
	put_cstring(&m, USERAUTH_SERVICE);
	if (tr_send(tr, &m) == 0 && tr_recv(tr, &m) == 0 && m.data[0] == SSH_MSG_SERVICE_ACCEPT) {
		rbuf r;
		rbuf_init(&r, m.data + 1, m.len - 1);
		rc = get_cstring(&r, name, sizeof name) == 0 && !strcmp(name, USERAUTH_SERVICE) ? 0 : -1;
	}
	wbuf_free(&m);
	return rc;
}

/* Signed directly, without the optional PK_OK query. The signature covers
 * string session_id || the request up to (not including) the signature. */
static void build_publickey(transport *tr, const auth_client_cfg *cfg, wbuf *req)
{
	wbuf blob, signed_data, sig;
	wbuf_init(&blob);
	wbuf_init(&signed_data);
	wbuf_init(&sig);
	sshkey_put_blob(&blob, cfg->key->pk);
	put_request_head(req, cfg->user, "publickey");
	put_bool(req, 1);
	put_cstring(req, SSHKEY_ED25519);
	put_string(req, blob.data, blob.len);
	put_string(&signed_data, tr->session_id, sizeof tr->session_id);
	put_raw(&signed_data, req->data, req->len);
	sshkey_sign(cfg->key, signed_data.data, signed_data.len, &sig);
	put_string(req, sig.data, sig.len);
	wbuf_free(&blob);
	wbuf_free(&signed_data);
	wbuf_free(&sig);
}

static void build_password(const auth_client_cfg *cfg, wbuf *req)
{
	put_request_head(req, cfg->user, "password");
	put_bool(req, 0);
	put_cstring(req, cfg->password);
}

int userauth_client(transport *tr, const auth_client_cfg *cfg)
{
	char methods[512];
	wbuf req;
	int rc;

	if (request_service(tr) < 0)
		return -1;
	wbuf_init(&req);
	put_request_head(&req, cfg->user, "none"); /* learn the methods */
	rc = tr_send(tr, &req) < 0 ? -1 : await_result(tr, methods, sizeof methods);

	if (rc == 0 && cfg->key && namelist_contains(methods, "publickey")) {
		wbuf_reset(&req);
		build_publickey(tr, cfg, &req);
		rc = tr_send(tr, &req) < 0 ? -1 : await_result(tr, methods, sizeof methods);
	}
	if (rc == 0 && cfg->password && namelist_contains(methods, "password")) {
		wbuf_reset(&req);
		build_password(cfg, &req);
		rc = tr_send(tr, &req) < 0 ? -1 : await_result(tr, methods, sizeof methods);
	}
	wbuf_free(&req);
	if (rc == 0)
		fprintf(stderr, "tunnel: authentication failed (server allows: %s)\n", methods);
	return rc == 1 ? 0 : -1;
}
