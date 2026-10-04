/* Server side of a "session" channel (RFC 4254 section 6): collects
 * pty-req/env, then runs a shell or command with a pty (forkpty) or
 * with three pipes, and exposes the child's fds to the event loop. */
#ifndef TUNNEL_SESSION_H
#define TUNNEL_SESSION_H

#include <sys/ioctl.h>
#include <sys/types.h>

#include "buf.h"

#define SESSION_ENV_MAX 16

typedef struct {
	pid_t pid;          /* 0 until started */
	int in_fd;          /* child's stdin (pty master when has_pty) */
	int out_fd, err_fd; /* -1 once drained */
	int has_pty;
	char term[64];
	struct winsize ws;
	char *env[SESSION_ENV_MAX];
	int nenv;
	wbuf to_child;     /* channel data not yet written to in_fd */
	int close_stdin;   /* peer sent EOF: close in_fd once drained */
	int reaped, status;
} session;

void session_init(session *s);
void session_free(session *s); /* closes fds, SIGHUPs a live child */

/* Applies a pre-start request ("pty-req", "env", "window-change").
 * Returns 0 if accepted, -1 if refused. */
int session_request(session *s, const char *type, rbuf *r);
/* Starts the user's shell (command NULL) or `shell -c command`. */
int session_start(session *s, const char *command);

/* Writes pending to_child data; returns bytes written (or -1). */
ssize_t session_flush_input(session *s);
/* Child has no more output and has exited (non-blocking check). */
int session_finished(session *s);

#endif
