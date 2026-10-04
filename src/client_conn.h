/* Client side of the connection protocol (RFC 4254): opens one session
 * channel, sends env/pty-req/exec-or-shell, relays stdio. */
#ifndef TUNNEL_CLIENT_CONN_H
#define TUNNEL_CLIENT_CONN_H

#include "transport.h"

typedef struct {
	const char *command; /* NULL for a shell */
	int want_pty;
	const char *const *env; /* "NAME" entries to forward from our environment */
	int nenv;
} client_session_cfg;

/* Returns the remote exit status (255 on error or signal). */
int client_session_run(transport *tr, const client_session_cfg *cfg);

#endif
