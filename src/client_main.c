/* tunnel: a minimal SSH-2 client. */
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "client_conn.h"
#include "knownhosts.h"
#include "sshkey.h"
#include "transport.h"
#include "userauth.h"

#define MAX_ENV 16

typedef struct {
	const char *file, *host;
	int port, strict;
} hostkey_policy;

static void usage(void)
{
	fprintf(stderr, "usage: tunnel [-p port] [-l user] [-i key] [-o known_hosts] [-S]\n"
			"              [-t | -T] [-E VAR]... host [command...]\n"
			"  password auth reads TUNNEL_PASSWORD from the environment\n");
	exit(2);
}

/* known_hosts policy: match accepts, mismatch refuses, unknown is
 * recorded (accept-new) unless -S was given. */
static int check_hostkey(const uint8_t pk[32], void *arg)
{
	const hostkey_policy *p = arg;
	char fp[64];
	sshkey_fingerprint(pk, fp, sizeof fp);
	switch (knownhosts_check(p->file, p->host, p->port, pk)) {
	case KH_MATCH:
		return 0;
	case KH_MISMATCH:
		fprintf(stderr, "tunnel: HOST KEY MISMATCH for %s (got %s); refusing\n", p->host, fp);
		return -1;
	case KH_UNKNOWN:
		break;
	}
	if (p->strict) {
		fprintf(stderr, "tunnel: unknown host key %s for %s (-S given)\n", fp, p->host);
		return -1;
	}
	fprintf(stderr, "tunnel: adding %s key %s to %s\n", p->host, fp, p->file);
	return knownhosts_add(p->file, p->host, p->port, pk);
}

static int dial(const char *host, int port)
{
	struct addrinfo hints = {.ai_socktype = SOCK_STREAM}, *res, *ai;
	char service[16];
	int fd = -1;
	snprintf(service, sizeof service, "%d", port);
	if (getaddrinfo(host, service, &hints, &res) != 0)
		return -1;
	for (ai = res; ai && fd < 0; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd >= 0 && connect(fd, ai->ai_addr, ai->ai_addrlen) < 0) {
			close(fd);
			fd = -1;
		}
	}
	freeaddrinfo(res);
	return fd;
}

/* Joins argv into one command string, as ssh does. */
static char *join_args(char **argv, int n)
{
	size_t len = 1;
	for (int i = 0; i < n; i++)
		len += strlen(argv[i]) + 1;
	char *s = calloc(1, len);
	for (int i = 0; s && i < n; i++) {
		if (i)
			strcat(s, " ");
		strcat(s, argv[i]);
	}
	return s;
}

int main(int argc, char **argv)
{
	struct passwd *pw = getpwuid(getuid());
	char khdefault[1024];
	const char *keyfile = NULL, *env[MAX_ENV];
	int opt, pty = -1, nenv = 0;
	hostkey_policy policy = {.port = 22};
	auth_client_cfg auth = {.user = pw ? pw->pw_name : "root"};

	snprintf(khdefault, sizeof khdefault, "%s/.ssh/known_hosts", pw ? pw->pw_dir : ".");
	policy.file = khdefault;
	while ((opt = getopt(argc, argv, "+p:l:i:o:StTE:")) != -1) {
		switch (opt) {
		case 'p': policy.port = atoi(optarg); break;
		case 'l': auth.user = optarg; break;
		case 'i': keyfile = optarg; break;
		case 'o': policy.file = optarg; break;
		case 'S': policy.strict = 1; break;
		case 't': pty = 1; break;
		case 'T': pty = 0; break;
		case 'E':
			if (nenv < MAX_ENV)
				env[nenv++] = optarg;
			break;
		default: usage();
		}
	}
	if (optind >= argc)
		usage();
	policy.host = argv[optind++];
	client_session_cfg sess = {.env = env, .nenv = nenv};
	sess.command = optind < argc ? join_args(argv + optind, argc - optind) : NULL;
	sess.want_pty = pty >= 0 ? pty : (!sess.command && isatty(0));

	if (sodium_init() < 0)
		return 255;
	ed25519_key key;
	if (keyfile) {
		if (sshkey_load_private(keyfile, &key) < 0) {
			fprintf(stderr, "tunnel: cannot load ed25519 key %s\n", keyfile);
			return 255;
		}
		auth.key = &key;
	}
	auth.password = getenv("TUNNEL_PASSWORD");

	signal(SIGPIPE, SIG_IGN);
	int fd = dial(policy.host, policy.port);
	if (fd < 0) {
		fprintf(stderr, "tunnel: cannot connect to %s:%d\n", policy.host, policy.port);
		return 255;
	}
	transport tr;
	if (tr_client_start(&tr, fd, check_hostkey, &policy) < 0) {
		fprintf(stderr, "tunnel: key exchange failed\n");
		return 255;
	}
	if (userauth_client(&tr, &auth) < 0)
		return 255;
	return client_session_run(&tr, &sess);
}
