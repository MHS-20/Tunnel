#include "knownhosts.h"

#include <stdio.h>
#include <string.h>

#include "sshkey.h"

static void host_pattern(char *out, size_t cap, const char *host, int port)
{
	if (port == 22)
		snprintf(out, cap, "%s", host);
	else
		snprintf(out, cap, "[%s]:%d", host, port);
}

/* Is `name` one of the comma-separated entries in field? */
static int field_has(const char *field, size_t flen, const char *name)
{
	size_t nl = strlen(name);
	for (const char *p = field, *end = field + flen; p < end;) {
		size_t n = strcspn(p, ",");
		if (n > (size_t)(end - p))
			n = (size_t)(end - p);
		if (n == nl && memcmp(p, name, n) == 0)
			return 1;
		p += n + 1;
	}
	return 0;
}

kh_result knownhosts_check(const char *file, const char *host, int port, const uint8_t pk[32])
{
	char want[300], line[4096];
	kh_result res = KH_UNKNOWN;
	FILE *f = fopen(file, "r");
	if (!f)
		return KH_UNKNOWN;
	host_pattern(want, sizeof want, host, port);
	while (fgets(line, sizeof line, f)) {
		const char *p = line + strspn(line, " \t");
		size_t hl = strcspn(p, " \t");
		uint8_t lk[32];
		if (*p == '#' || *p == '|' || *p == '@' || !field_has(p, hl, want))
			continue;
		if (sshkey_parse_publine(p + hl, lk) != 0)
			continue; /* some other key type for this host */
		if (memcmp(lk, pk, 32) == 0) {
			res = KH_MATCH;
			break;
		}
		res = KH_MISMATCH;
	}
	fclose(f);
	return res;
}

int knownhosts_add(const char *file, const char *host, int port, const uint8_t pk[32])
{
	char pat[300], pub[SSHKEY_PUBLINE_MAX];
	FILE *f = fopen(file, "a");
	if (!f)
		return -1;
	host_pattern(pat, sizeof pat, host, port);
	sshkey_format_publine(pk, pub, sizeof pub);
	fprintf(f, "%s %s\n", pat, pub);
	return fclose(f) == 0 ? 0 : -1;
}
