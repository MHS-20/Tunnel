/* Packet framing and chacha20-poly1305@openssh.com over a socketpair. */
#include <sodium.h>
#include <sys/socket.h>
#include <unistd.h>

#include "check.h"
#include "packet.h"
#include "version.h"

static void roundtrip(pkt_conn *a, pkt_conn *b, size_t len)
{
	uint8_t msg[PAYLOAD_MAX];
	for (size_t i = 0; i < len; i++)
		msg[i] = (uint8_t)(i * 7 + len);
	wbuf got;
	wbuf_init(&got);
	CHECK(pkt_send(a, msg, len) == 0);
	CHECK(pkt_recv(b, &got) == 0);
	CHECK(got.len == len && memcmp(got.data, msg, len) == 0);
	wbuf_free(&got);
}

int main(void)
{
	if (sodium_init() < 0)
		return 1;
	int sv[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	pkt_conn a, b;
	pkt_init(&a, sv[0]);
	pkt_init(&b, sv[1]);

	/* Plaintext framing: check the exact on-wire layout. */
	uint8_t one = 21, wire[64];
	CHECK(pkt_send(&a, &one, 1) == 0);
	CHECK(read(sv[1], wire, sizeof wire) == 16);
	CHECK(peek_u32(wire) == 12 && wire[4] == 10 && wire[5] == 21);
	b.rx.seq++;
	CHECK(a.tx.seq == 1);

	for (size_t len = 0; len < 40; len++)
		roundtrip(&a, &b, len);
	roundtrip(&a, &b, PAYLOAD_MAX);

	/* Switch on chacha20-poly1305 with matching keys. */
	uint8_t key[64];
	randombytes_buf(key, sizeof key);
	cipher_init(&a.tx.ctx, CIPHER_CHACHAPOLY, key);
	cipher_init(&b.rx.ctx, CIPHER_CHACHAPOLY, key);
	for (size_t len = 0; len < 40; len++)
		roundtrip(&a, &b, len);
	roundtrip(&a, &b, PAYLOAD_MAX);
	CHECK(a.tx.seq == b.rx.seq);

	/* Encrypted length hides the plaintext length; padding is aligned
	 * excluding the length field (AAD) and the tag follows. */
	uint8_t msg[3] = {1, 2, 3};
	CHECK(pkt_send(&a, msg, 3) == 0);
	ssize_t n = read(sv[1], wire, sizeof wire);
	CHECK(n == 4 + 8 + 16 || n == 4 + 16 + 16);
	CHECK((n - 4 - 16) % 8 == 0);
	b.rx.seq++;

	/* Tampering with a ciphertext byte fails authentication. */
	CHECK(pkt_send(&a, msg, 3) == 0);
	n = read(sv[1], wire, sizeof wire);
	wire[6] ^= 1;
	CHECK(cipher_open(&b.rx.ctx, b.rx.seq, wire, (size_t)n - 16, wire + n - 16) == -1);

	/* A wrong sequence number also fails (nonce binding). */
	CHECK(pkt_send(&a, msg, 3) == 0);
	n = read(sv[1], wire, sizeof wire);
	b.rx.seq += 2; /* correct would be +1 */
	CHECK(cipher_open(&b.rx.ctx, b.rx.seq, wire, (size_t)n - 16, wire + n - 16) == -1);
	b.rx.seq--;
	CHECK(cipher_open(&b.rx.ctx, b.rx.seq, wire, (size_t)n - 16, wire + n - 16) == 0);

	/* Version lines. */
	CHECK(version_check("SSH-2.0-OpenSSH_9.9") == 0);
	CHECK(version_check("SSH-1.99-Old") == 0);
	CHECK(version_check("SSH-1.5-Old") == -1);
	CHECK(version_check("SSH-2.0-") == -1);
	write(sv[0], "banner line\r\nSSH-2.0-Peer x\r\nrest", 33);
	char line[256];
	CHECK(version_recv(sv[1], line, sizeof line) == 0 && strcmp(line, "SSH-2.0-Peer x") == 0);
	CHECK(read(sv[1], line, 4) == 4 && memcmp(line, "rest", 4) == 0);
	return check_report("test_packet");
}
