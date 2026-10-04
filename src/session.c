#include "session.h"

#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

void session_init(session *s)
{
	memset(s, 0, sizeof *s);
	s->in_fd = s->out_fd = s->err_fd = -1;
	wbuf_init(&s->to_child);
}

static void close_fd(int *fd)
{
	if (*fd >= 0)
		close(*fd);
	*fd = -1;
}

void session_free(session *s)
{
	close_fd(&s->in_fd);
	close_fd(&s->out_fd);
	close_fd(&s->err_fd);
	if (s->pid > 0 && !s->reaped) {
		kill(s->pid, SIGHUP);
		waitpid(s->pid, NULL, 0);
	}
	for (int i = 0; i < s->nenv; i++)
		free(s->env[i]);
	wbuf_free(&s->to_child);
	memset(s, 0, sizeof *s);
}

static int read_winsize(rbuf *r, struct winsize *ws)
{
	ws->ws_col = (unsigned short)get_u32(r);
	ws->ws_row = (unsigned short)get_u32(r);
	ws->ws_xpixel = (unsigned short)get_u32(r);
	ws->ws_ypixel = (unsigned short)get_u32(r);
	return r->err ? -1 : 0;
}

/* Like OpenSSH's default AcceptEnv, only locale variables are passed. */
static int env_allowed(const char *name)
{
	return !strcmp(name, "LANG") || !strncmp(name, "LC_", 3);
}

int session_request(session *s, const char *type, rbuf *r)
{
	if (!strcmp(type, "pty-req")) {
		uint32_t n;
		if (s->pid || get_cstring(r, s->term, sizeof s->term) < 0 ||
		    read_winsize(r, &s->ws) < 0)
			return -1;
		get_string(r, &n); /* encoded terminal modes: not applied */
		s->has_pty = 1;
		return 0;
	}
	if (!strcmp(type, "env")) {
		char name[128], value[1024], *kv;
		if (s->pid || get_cstring(r, name, sizeof name) < 0 ||
		    get_cstring(r, value, sizeof value) < 0 || !env_allowed(name) ||
		    s->nenv == SESSION_ENV_MAX || asprintf(&kv, "%s=%s", name, value) < 0)
			return -1;
		s->env[s->nenv++] = kv;
		return 0;
	}
	if (!strcmp(type, "window-change")) {
		if (read_winsize(r, &s->ws) < 0)
			return -1;
		if (s->has_pty && s->in_fd >= 0)
			ioctl(s->in_fd, TIOCSWINSZ, &s->ws);
		return 0;
	}
	return -1;
}

/* In the child: environment, working directory, exec. */
static void exec_child(const session *s, const char *command)
{
	struct passwd *pw = getpwuid(getuid());
	const char *shell = pw && pw->pw_shell && *pw->pw_shell ? pw->pw_shell : "/bin/sh";
	const char *base = strrchr(shell, '/') ? strrchr(shell, '/') + 1 : shell;
	char argv0[256];

	signal(SIGPIPE, SIG_DFL);
	if (pw) {
		setenv("HOME", pw->pw_dir, 1);
		setenv("USER", pw->pw_name, 1);
		setenv("LOGNAME", pw->pw_name, 1);
		if (chdir(pw->pw_dir) < 0)
			chdir("/");
	}
	setenv("SHELL", shell, 1);
	if (s->has_pty)
		setenv("TERM", s->term, 1);
	for (int i = 0; i < s->nenv; i++)
		putenv(s->env[i]);

	if (command) {
		execl(shell, base, "-c", command, (char *)NULL);
	} else {
		snprintf(argv0, sizeof argv0, "-%s", base); /* login shell */
		execl(shell, argv0, (char *)NULL);
	}
	perror(shell);
	_exit(127);
}

static int start_pty(session *s, const char *command)
{
	int master;
	pid_t pid = forkpty(&master, NULL, NULL, &s->ws);
	if (pid < 0)
		return -1;
	if (pid == 0)
		exec_child(s, command);
	s->pid = pid;
	s->in_fd = master;
	s->out_fd = dup(master);
	return s->out_fd < 0 ? -1 : 0;
}

static int start_pipes(session *s, const char *command)
{
	int in[2], out[2], err[2];
	if (pipe(in) < 0)
		return -1;
	if (pipe(out) < 0 || pipe(err) < 0)
		return -1; /* fds leak only on this already-fatal path */
	pid_t pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		setsid();
		dup2(in[0], 0);
		dup2(out[1], 1);
		dup2(err[1], 2);
		for (int i = 0; i < 2; i++) {
			close(in[i]);
			close(out[i]);
			close(err[i]);
		}
		exec_child(s, command);
	}
	close(in[0]);
	close(out[1]);
	close(err[1]);
	s->pid = pid;
	s->in_fd = in[1];
	s->out_fd = out[0];
	s->err_fd = err[0];
	return 0;
}

int session_start(session *s, const char *command)
{
	if (s->pid)
		return -1;
	if ((s->has_pty ? start_pty : start_pipes)(s, command) < 0)
		return -1;
	fcntl(s->in_fd, F_SETFL, fcntl(s->in_fd, F_GETFL) | O_NONBLOCK);
	return 0;
}

ssize_t session_flush_input(session *s)
{
	if (s->in_fd < 0) {
		s->to_child.len = 0; /* child closed stdin: discard */
		return 0;
	}
	ssize_t n = s->to_child.len ? write(s->in_fd, s->to_child.data, s->to_child.len) : 0;
	if (n < 0 && (errno == EAGAIN || errno == EINTR))
		return 0;
	if (n < 0 && errno == EPIPE) {
		close_fd(&s->in_fd);
		s->to_child.len = 0;
		return 0;
	}
	if (n < 0)
		return -1;
	memmove(s->to_child.data, s->to_child.data + n, s->to_child.len - (size_t)n);
	s->to_child.len -= (size_t)n;
	if (s->to_child.len == 0 && s->close_stdin && !s->has_pty)
		close_fd(&s->in_fd);
	return n;
}

int session_finished(session *s)
{
	if (s->out_fd >= 0 || s->err_fd >= 0)
		return 0;
	if (!s->reaped) {
		pid_t r = waitpid(s->pid, &s->status, WNOHANG);
		if (r == 0)
			return 0;
		s->reaped = 1;
	}
	return 1;
}
