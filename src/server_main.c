/* tunneld: a minimal SSH-2 server. Runs as the invoking user; one forked
 * process per connection. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "server_conn.h"
#include "sshkey.h"
#include "transport.h"
#include "userauth.h"

static void usage(void)
{
	fprintf(stderr, "usage: tunneld -k host_key [-p port] [-b addr] [-a authorized_keys]\n"
			"               [-P password_file] [-u user]\n");
	exit(2);
}

static char *read_password_file(const char *path)
{
	static char pw[256];
	FILE *f = fopen(path, "r");
	if (!f || !fgets(pw, sizeof pw, f)) {
		perror(path);
		exit(1);
	}
	fclose(f);
	pw[strcspn(pw, "\r\n")] = 0;
	return pw;
}

static int listen_on(const char *addr, int port)
{
	struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
	int one = 1, fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0 || inet_pton(AF_INET, addr, &sa.sin_addr) != 1)
		return -1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0 || listen(fd, 16) < 0)
		return -1;
	return fd;
}

static void handle_connection(int fd, const ed25519_key *hostkey, const auth_server_cfg *auth)
{
	transport tr;
	if (tr_server_start(&tr, fd, hostkey) < 0) {
		fprintf(stderr, "tunneld: key exchange failed\n");
		return;
	}
	if (userauth_server(&tr, auth) < 0) {
		fprintf(stderr, "tunneld: authentication failed\n");
		return;
	}
	fprintf(stderr, "tunneld: %s authenticated (peer %s)\n", auth->user, tr.v_c);
	server_conn_run(&tr);
}

int main(int argc, char **argv)
{
	const char *keyfile = NULL, *addr = "127.0.0.1";
	int port = 2222, opt;
	struct passwd *pw = getpwuid(getuid());
	auth_server_cfg auth = {.user = pw ? pw->pw_name : "root"};

	while ((opt = getopt(argc, argv, "k:p:b:a:P:u:")) != -1) {
		switch (opt) {
		case 'k': keyfile = optarg; break;
		case 'p': port = atoi(optarg); break;
		case 'b': addr = optarg; break;
		case 'a': auth.authorized_keys = optarg; break;
		case 'P': auth.password = read_password_file(optarg); break;
		case 'u': auth.user = optarg; break;
		default: usage();
		}
	}
	if (!keyfile)
		usage();
	if (sodium_init() < 0)
		return 1;
	ed25519_key hostkey;
	if (sshkey_load_private(keyfile, &hostkey) < 0) {
		fprintf(stderr, "tunneld: cannot load ed25519 host key %s\n", keyfile);
		return 1;
	}
	int lfd = listen_on(addr, port);
	if (lfd < 0) {
		perror("tunneld: listen");
		return 1;
	}
	char fp[64];
	sshkey_fingerprint(hostkey.pk, fp, sizeof fp);
	fprintf(stderr, "tunneld: listening on %s:%d, host key %s\n", addr, port, fp);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN); /* connection processes reap themselves */
	for (;;) {
		int fd = accept(lfd, NULL, NULL);
		if (fd < 0)
			continue;
		pid_t pid = fork();
		if (pid == 0) {
			close(lfd);
			signal(SIGCHLD, SIG_DFL); /* sessions need waitpid */
			handle_connection(fd, &hostkey, &auth);
			_exit(0);
		}
		close(fd);
	}
}
