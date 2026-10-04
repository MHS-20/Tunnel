/* User authentication protocol (RFC 4252) on top of the "ssh-userauth"
 * service request: "none", "publickey" (ssh-ed25519) and "password". */
#ifndef TUNNEL_USERAUTH_H
#define TUNNEL_USERAUTH_H

#include <stddef.h>

#include "sshkey.h"
#include "transport.h"

#define USERAUTH_SERVICE "ssh-userauth"
#define CONNECTION_SERVICE "ssh-connection"

typedef struct {
	const char *user;
	const ed25519_key *key; /* NULL to skip publickey */
	const char *password;   /* NULL to skip password */
} auth_client_cfg;

typedef struct {
	const char *user;            /* the only user accepted */
	const char *authorized_keys; /* NULL disables publickey */
	const char *password;        /* NULL disables password */
} auth_server_cfg;

int userauth_client(transport *tr, const auth_client_cfg *cfg);
int userauth_server(transport *tr, const auth_server_cfg *cfg);

#endif
