#include "server_conn.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "channel.h"
#include "session.h"
#include "ssh_msg.h"

#define REAP_POLL_MS 50

typedef struct {
	transport *tr;
	chan_table chans;
	session sessions[CHAN_MAX]; /* indexed by local channel id */
} server_conn;

static session *sess_of(server_conn *sc, const channel *c) { return &sc->sessions[c->local_id]; }

static void destroy_channel(server_conn *sc, channel *c)
{
	session_free(sess_of(sc, c));
	chan_free(c);
}

static void on_global_request(server_conn *sc, rbuf *r)
{
	char name[128];
	get_cstring(r, name, sizeof name);
	if (get_bool(r)) {
		wbuf w;
		wbuf_init(&w);
		put_u8(&w, SSH_MSG_REQUEST_FAILURE); /* none supported */
		tr_send(sc->tr, &w);
		wbuf_free(&w);
	}
}

static void on_open(server_conn *sc, rbuf *r)
{
	char type[64];
	wbuf w;
	get_cstring(r, type, sizeof type);
	uint32_t sender = get_u32(r), window = get_u32(r), maxpkt = get_u32(r);
	channel *c = NULL;
	uint32_t reason = SSH_OPEN_UNKNOWN_CHANNEL_TYPE;

	if (!r->err && !strcmp(type, "session")) {
		c = chan_new(&sc->chans);
		reason = SSH_OPEN_RESOURCE_SHORTAGE;
	}
	wbuf_init(&w);
	if (c) {
		c->remote_id = sender;
		c->remote_window = window;
		c->remote_maxpkt = maxpkt;
		session_init(sess_of(sc, c));
		chan_msg_begin(&w, SSH_MSG_CHANNEL_OPEN_CONFIRMATION, c);
		put_u32(&w, c->local_id);
		put_u32(&w, c->local_window);
		put_u32(&w, CHAN_MAXPKT);
	} else {
		put_u8(&w, SSH_MSG_CHANNEL_OPEN_FAILURE);
		put_u32(&w, sender);
		put_u32(&w, reason);
		put_cstring(&w, "channel type not supported");
		put_cstring(&w, "");
	}
	tr_send(sc->tr, &w);
	wbuf_free(&w);
}

static void on_request(server_conn *sc, channel *c, rbuf *r)
{
	char type[64], command[8192];
	session *s = sess_of(sc, c);
	get_cstring(r, type, sizeof type);
	int want_reply = get_bool(r);
	int ok = -1;

	if (r->err)
		ok = -1;
	else if (!strcmp(type, "shell"))
		ok = session_start(s, NULL);
	else if (!strcmp(type, "exec"))
		ok = get_cstring(r, command, sizeof command) < 0 ? -1 : session_start(s, command);
	else
		ok = session_request(s, type, r); /* pty-req, env, window-change */

	if (want_reply)
		chan_send_simple(sc->tr, c, ok == 0 ? SSH_MSG_CHANNEL_SUCCESS : SSH_MSG_CHANNEL_FAILURE);
}

static void on_data(server_conn *sc, channel *c, rbuf *r)
{
	uint32_t n;
	const uint8_t *p = get_string(r, &n);
	session *s = sess_of(sc, c);
	if (r->err || chan_on_data(c, n) < 0 || c->recv_eof) {
		tr_disconnect(sc->tr, SSH_DISCONNECT_PROTOCOL_ERROR, "channel window exceeded");
		return;
	}
	put_raw(&s->to_child, p, n);
}

/* Messages addressed to an existing channel. */
static void on_channel_msg(server_conn *sc, uint8_t type, channel *c, rbuf *r)
{
	session *s = sess_of(sc, c);
	switch (type) {
	case SSH_MSG_CHANNEL_DATA:
		on_data(sc, c, r);
		break;
	case SSH_MSG_CHANNEL_WINDOW_ADJUST:
		chan_on_window_adjust(c, get_u32(r));
		break;
	case SSH_MSG_CHANNEL_REQUEST:
		on_request(sc, c, r);
		break;
	case SSH_MSG_CHANNEL_EOF:
		c->recv_eof = 1;
		s->close_stdin = 1;
		session_flush_input(s);
		break;
	case SSH_MSG_CHANNEL_CLOSE:
		c->recv_close = 1;
		chan_send_close(sc->tr, c);
		destroy_channel(sc, c);
		break;
	case SSH_MSG_CHANNEL_EXTENDED_DATA: /* ignored for sessions */
		break;
	default:
		tr_unimplemented(sc->tr);
	}
}

/* Returns -1 when the transport is gone. */
static int on_message(server_conn *sc, const wbuf *m)
{
	rbuf r;
	uint8_t type = m->data[0];
	rbuf_init(&r, m->data + 1, m->len - 1);
	if (type == SSH_MSG_GLOBAL_REQUEST)
		on_global_request(sc, &r);
	else if (type == SSH_MSG_CHANNEL_OPEN)
		on_open(sc, &r);
	else if (type >= SSH_MSG_CHANNEL_WINDOW_ADJUST && type <= SSH_MSG_CHANNEL_FAILURE) {
		channel *c = chan_get(&sc->chans, get_u32(&r));
		if (!c)
			return -1;
		if (c->sent_close && type != SSH_MSG_CHANNEL_CLOSE)
			return 0; /* late messages after our CLOSE are allowed */
		on_channel_msg(sc, type, c, &r);
	} else
		tr_unimplemented(sc->tr);
	return 0;
}

/* Child output -> channel, bounded by the peer's window. */
static void pump_output(server_conn *sc, channel *c, int *fd, uint32_t ext)
{
	uint8_t buf[CHAN_MAXPKT];
	size_t room = chan_send_room(c);
	if (room > sizeof buf)
		room = sizeof buf;
	ssize_t n = read(*fd, buf, room);
	if (n < 0 && (errno == EAGAIN || errno == EINTR))
		return;
	if (n <= 0) { /* EOF, or EIO from a pty whose slave side is gone */
		close(*fd);
		*fd = -1;
		return;
	}
	chan_send_data(sc->tr, c, ext, buf, (size_t)n);
}

static void send_exit(server_conn *sc, channel *c)
{
	session *s = sess_of(sc, c);
	wbuf w;
	wbuf_init(&w);
	if (WIFSIGNALED(s->status)) {
		const char *name = sigabbrev_np(WTERMSIG(s->status));
		chan_request_begin(&w, c, "exit-signal", 0);
		put_cstring(&w, name ? name : "KILL");
		put_bool(&w, WCOREDUMP(s->status));
		put_cstring(&w, "");
		put_cstring(&w, "");
	} else {
		chan_request_begin(&w, c, "exit-status", 0);
		put_u32(&w, (uint32_t)WEXITSTATUS(s->status));
	}
	tr_send(sc->tr, &w);
	wbuf_free(&w);
	chan_send_eof(sc->tr, c);
	chan_send_close(sc->tr, c);
}

/* Builds the poll set: [0] is the transport, then per-channel fds. */
static nfds_t build_pollset(server_conn *sc, struct pollfd *pfd, channel **owner)
{
	nfds_t n = 1;
	pfd[0] = (struct pollfd){.fd = sc->tr->pc.fd, .events = POLLIN};
	for (int i = 0; i < CHAN_MAX; i++) {
		channel *c = &sc->chans.ch[i];
		session *s = &sc->sessions[i];
		if (!c->used || !s->pid || c->sent_close)
			continue;
		if (chan_send_room(c) > 0) { /* else wait for WINDOW_ADJUST */
			if (s->out_fd >= 0)
				pfd[n] = (struct pollfd){.fd = s->out_fd, .events = POLLIN}, owner[n++] = c;
			if (s->err_fd >= 0)
				pfd[n] = (struct pollfd){.fd = s->err_fd, .events = POLLIN}, owner[n++] = c;
		}
		if (s->in_fd >= 0 && s->to_child.len)
			pfd[n] = (struct pollfd){.fd = s->in_fd, .events = POLLOUT}, owner[n++] = c;
	}
	return n;
}

static int service_children(server_conn *sc)
{
	int waiting = 0;
	for (int i = 0; i < CHAN_MAX; i++) {
		channel *c = &sc->chans.ch[i];
		session *s = &sc->sessions[i];
		if (!c->used || !s->pid || c->sent_close)
			continue;
		ssize_t w = session_flush_input(s);
		if (w > 0)
			chan_delivered(sc->tr, c, (size_t)w);
		if (session_finished(s))
			send_exit(sc, c);
		else if (s->out_fd < 0 && s->err_fd < 0)
			waiting = 1; /* output drained, child not yet reaped */
	}
	return waiting;
}

void server_conn_run(transport *tr)
{
	server_conn *sc = calloc(1, sizeof *sc);
	wbuf m;
	if (!sc)
		return;
	sc->tr = tr;
	wbuf_init(&m);
	for (;;) {
		struct pollfd pfd[1 + 3 * CHAN_MAX];
		channel *owner[1 + 3 * CHAN_MAX];
		int waiting = service_children(sc);
		nfds_t n = build_pollset(sc, pfd, owner);
		if (poll(pfd, n, waiting ? REAP_POLL_MS : -1) < 0 && errno != EINTR)
			break;
		if (pfd[0].revents) {
			if (tr_recv(tr, &m) < 0 || on_message(sc, &m) < 0)
				break;
			continue; /* channel table may have changed */
		}
		for (nfds_t i = 1; i < n; i++) {
			if (!(pfd[i].revents & (POLLIN | POLLHUP | POLLERR)) || pfd[i].events != POLLIN)
				continue;
			session *s = sess_of(sc, owner[i]);
			if (pfd[i].fd == s->out_fd)
				pump_output(sc, owner[i], &s->out_fd, 0);
			else if (pfd[i].fd == s->err_fd)
				pump_output(sc, owner[i], &s->err_fd, SSH_EXTENDED_DATA_STDERR);
		}
	}
	for (int i = 0; i < CHAN_MAX; i++)
		if (sc->chans.ch[i].used)
			destroy_channel(sc, &sc->chans.ch[i]);
	wbuf_free(&m);
	free(sc);
}
