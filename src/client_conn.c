#include "client_conn.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include "channel.h"
#include "io.h"
#include "ssh_msg.h"

#define MAX_PENDING_REPLIES 8

typedef struct {
	transport *tr;
	chan_table chans;
	channel *ch;
	int open;
	/* Request types awaiting SUCCESS/FAILURE, answered in order. */
	const char *pending[MAX_PENDING_REPLIES];
	int npending;
	int exit_status;
	int stdin_open;
	int done;
} client_conn;

static struct termios saved_tio;
static int tio_saved;

static void restore_tty(void)
{
	if (tio_saved)
		tcsetattr(0, TCSADRAIN, &saved_tio);
}

static void enter_raw_mode(void)
{
	struct termios tio;
	if (tcgetattr(0, &saved_tio) < 0)
		return;
	tio_saved = 1;
	atexit(restore_tty);
	tio = saved_tio;
	cfmakeraw(&tio);
	tcsetattr(0, TCSADRAIN, &tio);
}

static int send_open(client_conn *cc)
{
	wbuf w;
	wbuf_init(&w);
	put_u8(&w, SSH_MSG_CHANNEL_OPEN);
	put_cstring(&w, "session");
	put_u32(&w, cc->ch->local_id);
	put_u32(&w, cc->ch->local_window);
	put_u32(&w, CHAN_MAXPKT);
	int rc = tr_send(cc->tr, &w);
	wbuf_free(&w);
	return rc;
}

static int send_request(client_conn *cc, wbuf *w, const char *type, int want_reply)
{
	if (want_reply) {
		if (cc->npending == MAX_PENDING_REPLIES)
			return -1;
		cc->pending[cc->npending++] = type;
	}
	int rc = tr_send(cc->tr, w);
	wbuf_reset(w);
	return rc;
}

/* After OPEN_CONFIRMATION: env, pty-req, then exec or shell. */
static int send_session_requests(client_conn *cc, const client_session_cfg *cfg)
{
	wbuf w;
	int rc = 0;
	wbuf_init(&w);
	for (int i = 0; i < cfg->nenv && rc == 0; i++) {
		const char *v = getenv(cfg->env[i]);
		if (!v)
			continue;
		chan_request_begin(&w, cc->ch, "env", 0);
		put_cstring(&w, cfg->env[i]);
		put_cstring(&w, v);
		rc = send_request(cc, &w, "env", 0);
	}
	if (rc == 0 && cfg->want_pty) {
		struct winsize ws = {.ws_row = 24, .ws_col = 80};
		const char *term = getenv("TERM");
		ioctl(0, TIOCGWINSZ, &ws);
		chan_request_begin(&w, cc->ch, "pty-req", 1);
		put_cstring(&w, term ? term : "vt100");
		put_u32(&w, ws.ws_col);
		put_u32(&w, ws.ws_row);
		put_u32(&w, ws.ws_xpixel);
		put_u32(&w, ws.ws_ypixel);
		put_string(&w, "", 1); /* modes: just TTY_OP_END */
		rc = send_request(cc, &w, "pty-req", 1);
	}
	if (rc == 0) {
		const char *type = cfg->command ? "exec" : "shell";
		chan_request_begin(&w, cc->ch, type, 1);
		if (cfg->command)
			put_cstring(&w, cfg->command);
		rc = send_request(cc, &w, type, 1);
	}
	wbuf_free(&w);
	return rc;
}

static int on_reply(client_conn *cc, int success)
{
	if (cc->npending == 0)
		return -1;
	const char *type = cc->pending[0];
	memmove(cc->pending, cc->pending + 1, --cc->npending * sizeof cc->pending[0]);
	if (success)
		return 0;
	fprintf(stderr, "tunnel: server refused %s request\n", type);
	return strcmp(type, "pty-req") == 0 ? 0 : -1; /* a missing pty is not fatal */
}

static void on_server_request(client_conn *cc, rbuf *r)
{
	char type[64];
	get_cstring(r, type, sizeof type);
	int want_reply = get_bool(r);
	if (!strcmp(type, "exit-status")) {
		cc->exit_status = (int)get_u32(r);
	} else if (!strcmp(type, "exit-signal")) {
		char sig[32];
		get_cstring(r, sig, sizeof sig);
		fprintf(stderr, "tunnel: remote command killed by signal %s\n", sig);
		cc->exit_status = 255;
	}
	if (want_reply)
		chan_send_simple(cc->tr, cc->ch, SSH_MSG_CHANNEL_FAILURE);
}

static int on_data(client_conn *cc, rbuf *r, int fd)
{
	uint32_t n;
	const uint8_t *p = get_string(r, &n);
	if (r->err || chan_on_data(cc->ch, n) < 0)
		return -1;
	if (write_full(fd, p, n) < 0)
		return -1;
	return chan_delivered(cc->tr, cc->ch, n);
}

static int on_message(client_conn *cc, const client_session_cfg *cfg, const wbuf *m)
{
	rbuf r;
	uint8_t type = m->data[0];
	rbuf_init(&r, m->data + 1, m->len - 1);
	if (type == SSH_MSG_GLOBAL_REQUEST) {
		char name[128];
		get_cstring(&r, name, sizeof name);
		if (get_bool(&r)) {
			uint8_t fail = SSH_MSG_REQUEST_FAILURE;
			return pkt_send(&cc->tr->pc, &fail, 1);
		}
		return 0;
	}
	if (type < SSH_MSG_CHANNEL_OPEN_CONFIRMATION || type > SSH_MSG_CHANNEL_FAILURE) {
		tr_unimplemented(cc->tr);
		return 0;
	}
	if (get_u32(&r) != cc->ch->local_id)
		return -1;

	switch (type) {
	case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
		cc->ch->remote_id = get_u32(&r);
		cc->ch->remote_window = get_u32(&r);
		cc->ch->remote_maxpkt = get_u32(&r);
		cc->open = 1;
		return r.err ? -1 : send_session_requests(cc, cfg);
	case SSH_MSG_CHANNEL_OPEN_FAILURE:
		fprintf(stderr, "tunnel: server refused to open a session\n");
		return -1;
	case SSH_MSG_CHANNEL_WINDOW_ADJUST:
		chan_on_window_adjust(cc->ch, get_u32(&r));
		return 0;
	case SSH_MSG_CHANNEL_DATA:
		return on_data(cc, &r, 1);
	case SSH_MSG_CHANNEL_EXTENDED_DATA:
		get_u32(&r); /* data type code: stderr is the only one defined */
		return on_data(cc, &r, 2);
	case SSH_MSG_CHANNEL_EOF:
		cc->ch->recv_eof = 1;
		return 0;
	case SSH_MSG_CHANNEL_CLOSE:
		cc->ch->recv_close = 1;
		cc->done = 1;
		return chan_send_close(cc->tr, cc->ch);
	case SSH_MSG_CHANNEL_REQUEST:
		on_server_request(cc, &r);
		return 0;
	case SSH_MSG_CHANNEL_SUCCESS:
	case SSH_MSG_CHANNEL_FAILURE:
		return on_reply(cc, type == SSH_MSG_CHANNEL_SUCCESS);
	}
	return 0;
}

/* stdin -> channel, never more than the peer's window allows. */
static int pump_stdin(client_conn *cc)
{
	uint8_t buf[CHAN_MAXPKT];
	size_t room = chan_send_room(cc->ch);
	if (room > sizeof buf)
		room = sizeof buf;
	ssize_t n = read(0, buf, room);
	if (n < 0 && (errno == EINTR || errno == EAGAIN))
		return 0;
	if (n <= 0) {
		cc->stdin_open = 0;
		return chan_send_eof(cc->tr, cc->ch);
	}
	return chan_send_data(cc->tr, cc->ch, 0, buf, (size_t)n);
}

int client_session_run(transport *tr, const client_session_cfg *cfg)
{
	client_conn cc = {.tr = tr, .exit_status = 255, .stdin_open = 1};
	wbuf m;
	int failed = 0;

	cc.ch = chan_new(&cc.chans);
	if (send_open(&cc) < 0)
		return 255;
	if (cfg->want_pty && isatty(0))
		enter_raw_mode();
	wbuf_init(&m);
	while (!cc.done && !failed) {
		struct pollfd pfd[2] = {{.fd = tr->pc.fd, .events = POLLIN}, {.fd = 0}};
		int stdin_ready = cc.open && cc.stdin_open && chan_send_room(cc.ch) > 0;
		nfds_t n = stdin_ready ? 2 : 1;
		pfd[1].events = POLLIN;
		if (poll(pfd, n, -1) < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (pfd[0].revents)
			failed = tr_recv(tr, &m) < 0 || on_message(&cc, cfg, &m) < 0;
		else if (n == 2 && pfd[1].revents)
			failed = pump_stdin(&cc) < 0;
	}
	wbuf_free(&m);
	restore_tty();
	tr_disconnect(tr, SSH_DISCONNECT_BY_APPLICATION, "disconnected by user");
	return failed ? 255 : cc.exit_status;
}
