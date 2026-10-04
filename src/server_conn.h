/* Server side of the connection protocol (RFC 4254): an event loop that
 * multiplexes the transport and the session children of all channels. */
#ifndef TUNNEL_SERVER_CONN_H
#define TUNNEL_SERVER_CONN_H

#include "transport.h"

/* Runs until the client disconnects. */
void server_conn_run(transport *tr);

#endif
