/* The SSH transport layer (RFC 4253): version exchange, key exchange,
 * NEWKEYS, and a message stream that hides transport-level messages
 * (IGNORE, DEBUG, peer-initiated re-exchange) from the layers above. */
#ifndef TUNNEL_TRANSPORT_H
#define TUNNEL_TRANSPORT_H

#include <stdint.h>

#include "buf.h"
#include "packet.h"
#include "sshkey.h"
#include "version.h"

/* Client-side host key policy: return 0 to accept the key. */
typedef int (*hostkey_check_fn)(const uint8_t pk[32], void *arg);

typedef struct {
	pkt_conn pc;
	int is_server;
	char v_c[VERSION_MAX + 1], v_s[VERSION_MAX + 1];
	uint8_t session_id[32];
	int have_session_id;
	int strict; /* kex-strict-*-v00@openssh.com agreed (Terrapin fix) */
	const ed25519_key *hostkey;      /* server */
	hostkey_check_fn check_hostkey;  /* client */
	void *check_arg;
} transport;

int tr_client_start(transport *tr, int fd, hostkey_check_fn check, void *arg);
int tr_server_start(transport *tr, int fd, const ed25519_key *hostkey);

int tr_send(transport *tr, const wbuf *payload);
/* Next message for the upper layers; -1 on EOF, error or DISCONNECT. */
int tr_recv(transport *tr, wbuf *payload);
void tr_unimplemented(transport *tr); /* reply to the last received packet */
void tr_disconnect(transport *tr, uint32_t reason, const char *desc);

#endif
