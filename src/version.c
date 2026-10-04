#include "version.h"

#include <string.h>

#include "io.h"

int version_send(int fd, const char *ident)
{
	if (write_full(fd, ident, strlen(ident)) < 0)
		return -1;
	return write_full(fd, "\r\n", 2);
}

int version_check(const char *line)
{
	if (strncmp(line, "SSH-2.0-", 8) != 0 && strncmp(line, "SSH-1.99-", 9) != 0)
		return -1;
	/* softwareversion must be non-empty printable US-ASCII */
	const char *sw = strchr(line + 4, '-') + 1;
	if (*sw == 0 || *sw == ' ')
		return -1;
	for (const char *p = line; *p; p++)
		if (*p < 0x20 || *p > 0x7e)
			return -1;
	return 0;
}

/* Byte at a time: anything read past the LF belongs to the packet layer. */
static int read_line(int fd, char *out, size_t cap)
{
	size_t n = 0;
	for (;;) {
		char c;
		if (read_full(fd, &c, 1) < 0)
			return -1;
		if (c == '\n')
			break;
		if (n + 1 >= cap)
			return -1;
		out[n++] = c;
	}
	if (n > 0 && out[n - 1] == '\r')
		n--;
	out[n] = 0;
	return 0;
}

int version_recv(int fd, char *out, size_t cap)
{
	/* Servers may send other lines first; bound how many we tolerate. */
	for (int lines = 0; lines < 64; lines++) {
		char line[1024];
		if (read_line(fd, line, sizeof line) < 0)
			return -1;
		if (strncmp(line, "SSH-", 4) != 0)
			continue;
		if (strlen(line) + 2 > VERSION_MAX || strlen(line) >= cap ||
		    version_check(line) < 0)
			return -1;
		strcpy(out, line);
		return 0;
	}
	return -1;
}
