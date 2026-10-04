/* Minimal assertion harness shared by the unit tests. */
#ifndef TUNNEL_CHECK_H
#define TUNNEL_CHECK_H

#include <stdio.h>
#include <string.h>

static int check_failures, check_count;

#define CHECK(cond)                                                          \
	do {                                                                 \
		check_count++;                                               \
		if (!(cond)) {                                               \
			check_failures++;                                    \
			fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, \
				__LINE__, #cond);                            \
		}                                                            \
	} while (0)

#define CHECK_MEM(a, b, n) CHECK(memcmp((a), (b), (n)) == 0)

static inline size_t unhex(const char *hex, unsigned char *out)
{
	size_t n = 0;
	for (; hex[0] && hex[1]; hex += 2) {
		unsigned v;
		sscanf(hex, "%2x", &v);
		out[n++] = (unsigned char)v;
	}
	return n;
}

static inline int check_report(const char *name)
{
	printf("%-16s %d/%d checks passed\n", name, check_count - check_failures,
	       check_count);
	return check_failures ? 1 : 0;
}

#endif
