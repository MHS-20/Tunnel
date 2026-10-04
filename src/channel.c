#include "channel.h"

#include <string.h>

#include "ssh_msg.h"

/* Headroom inside PAYLOAD_MAX for the DATA message header. */
#define DATA_HEADER 13

channel *chan_new(chan_table *t)
{
	for (uint32_t i = 0; i < CHAN_MAX; i++) {
		channel *c = &t->ch[i];
		if (!c->used) {
			memset(c, 0, sizeof *c);
			c->used = 1;
			c->local_id = i;
			c->local_window = CHAN_WINDOW;
			return c;
		}
	}
	return NULL;
}

channel *chan_get(chan_table *t, uint32_t local_id)
{
	if (local_id >= CHAN_MAX || !t->ch[local_id].used)
		return NULL;
	return &t->ch[local_id];
}

void chan_free(channel *c) { memset(c, 0, sizeof *c); }

size_t chan_send_room(const channel *c)
{
	if (c->sent_eof || c->sent_close)
		return 0;
	size_t room = c->remote_window;
	if (room > c->remote_maxpkt)
		room = c->remote_maxpkt;
	if (room > PAYLOAD_MAX - DATA_HEADER)
		room = PAYLOAD_MAX - DATA_HEADER;
	return room;
}

void chan_msg_begin(wbuf *w, uint8_t msg, const channel *c)
{
	put_u8(w, msg);
	put_u32(w, c->remote_id);
}

void chan_request_begin(wbuf *w, const channel *c, const char *type, int want_reply)
{
	chan_msg_begin(w, SSH_MSG_CHANNEL_REQUEST, c);
	put_cstring(w, type);
	put_bool(w, want_reply);
}

static int send_and_free(transport *tr, wbuf *w)
{
	int rc = tr_send(tr, w);
	wbuf_free(w);
	return rc;
}

int chan_send_data(transport *tr, channel *c, uint32_t ext, const uint8_t *p, size_t len)
{
	wbuf w;
	if (len > chan_send_room(c))
		return -1;
	wbuf_init(&w);
	chan_msg_begin(&w, ext ? SSH_MSG_CHANNEL_EXTENDED_DATA : SSH_MSG_CHANNEL_DATA, c);
	if (ext)
		put_u32(&w, ext);
	put_string(&w, p, len);
	c->remote_window -= (uint32_t)len;
	return send_and_free(tr, &w);
}

int chan_on_data(channel *c, size_t n)
{
	if (n > c->local_window)
		return -1;
	c->local_window -= (uint32_t)n;
	return 0;
}

int chan_delivered(transport *tr, channel *c, size_t n)
{
	c->delivered += (uint32_t)n;
	if (c->delivered < CHAN_WINDOW / 2 || c->recv_eof || c->sent_close)
		return 0;
	wbuf w;
	wbuf_init(&w);
	chan_msg_begin(&w, SSH_MSG_CHANNEL_WINDOW_ADJUST, c);
	put_u32(&w, c->delivered);
	c->local_window += c->delivered;
	c->delivered = 0;
	return send_and_free(tr, &w);
}

void chan_on_window_adjust(channel *c, uint32_t n)
{
	/* RFC 4254 5.2: the window may not exceed 2^32 - 1. */
	c->remote_window = n > UINT32_MAX - c->remote_window ? UINT32_MAX : c->remote_window + n;
}

int chan_send_simple(transport *tr, const channel *c, uint8_t msg)
{
	wbuf w;
	wbuf_init(&w);
	chan_msg_begin(&w, msg, c);
	return send_and_free(tr, &w);
}

int chan_send_eof(transport *tr, channel *c)
{
	if (c->sent_eof || c->sent_close)
		return 0;
	c->sent_eof = 1;
	return chan_send_simple(tr, c, SSH_MSG_CHANNEL_EOF);
}

int chan_send_close(transport *tr, channel *c)
{
	if (c->sent_close)
		return 0;
	c->sent_close = 1;
	return chan_send_simple(tr, c, SSH_MSG_CHANNEL_CLOSE);
}
