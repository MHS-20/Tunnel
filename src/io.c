#include "io.h"

#include <errno.h>
#include <stdint.h>
#include <unistd.h>

int read_full(int fd, void *p, size_t n)
{
	uint8_t *b = p;
	while (n > 0) {
		ssize_t r = read(fd, b, n);
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			return -1;
		b += r;
		n -= (size_t)r;
	}
	return 0;
}

int write_full(int fd, const void *p, size_t n)
{
	const uint8_t *b = p;
	while (n > 0) {
		ssize_t r = write(fd, b, n);
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			return -1;
		b += r;
		n -= (size_t)r;
	}
	return 0;
}
