/* Channel bookkeeping for the connection protocol (RFC 4254 section 5):
 * id mapping, flow-control windows in both directions, EOF/CLOSE state.
 * What flows through a channel (a session, a socket...) lives elsewhere. */
#ifndef TUNNEL_CHANNEL_H
#define TUNNEL_CHANNEL_H

#include <stddef.h>
#include <stdint.h>

#include "transport.h"

#define CHAN_MAX 16
#define CHAN_WINDOW (2u * 1024 * 1024) /* our initial window */
#define CHAN_MAXPKT 32768u             /* largest data payload we accept */

typedef struct {
	int used;
	uint32_t local_id, remote_id;
	uint32_t local_window; /* credit the peer still has towards us */
	uint32_t delivered;    /* consumed since our last WINDOW_ADJUST */
	uint32_t remote_window, remote_maxpkt;
	int sent_eof, recv_eof, sent_close, recv_close;
	void *app; /* owner-specific state (e.g. a server session) */
} channel;

typedef struct {
	channel ch[CHAN_MAX];
} chan_table;

channel *chan_new(chan_table *t);
channel *chan_get(chan_table *t, uint32_t local_id);
void chan_free(channel *c);

/* Bytes we may send right now in one DATA message. */
size_t chan_send_room(const channel *c);
/* len must be <= chan_send_room(); ext 0 means CHANNEL_DATA. */
int chan_send_data(transport *tr, channel *c, uint32_t ext, const uint8_t *p, size_t len);
/* Peer sent us n bytes: -1 if that overruns the window we granted. */
int chan_on_data(channel *c, size_t n);
/* n bytes reached their destination: re-grant window when worthwhile. */
int chan_delivered(transport *tr, channel *c, size_t n);
void chan_on_window_adjust(channel *c, uint32_t n);

/* Writes "byte msg, uint32 recipient" for c into w. */
void chan_msg_begin(wbuf *w, uint8_t msg, const channel *c);
/* ... plus "string type, bool want_reply" for CHANNEL_REQUEST. */
void chan_request_begin(wbuf *w, const channel *c, const char *type, int want_reply);
int chan_send_simple(transport *tr, const channel *c, uint8_t msg);
int chan_send_eof(transport *tr, channel *c);
int chan_send_close(transport *tr, channel *c);

#endif
