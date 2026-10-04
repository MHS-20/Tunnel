#include "authkeys.h"

#include <stdio.h>
#include <string.h>

#include "sshkey.h"

int authkeys_allowed(const char *file, const uint8_t pk[32])
{
	char line[4096];
	uint8_t k[32];
	int found = 0;
	FILE *f = file ? fopen(file, "r") : NULL;
	if (!f)
		return 0;
	while (!found && fgets(line, sizeof line, f))
		found = sshkey_parse_publine(line, k) == 0 && memcmp(k, pk, 32) == 0;
	fclose(f);
	return found;
}
