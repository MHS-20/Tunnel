#include "packet.h"

#include <sodium.h>
#include <string.h>

#include "io.h"

void pkt_init(pkt_conn *pc, int fd)
{
	memset(pc, 0, sizeof *pc);
	pc->fd = fd;
	cipher_init(&pc->tx.ctx, CIPHER_NONE, NULL);
	cipher_init(&pc->rx.ctx, CIPHER_NONE, NULL);
}

/* At least 4 bytes of padding, making the encrypted part a multiple of the
 * block size (the length field counts unless the cipher treats it as AAD). */
static size_t padding_for(const cipher_ctx *c, size_t payload_len)
{
	size_t bs = cipher_block_size(c);
	size_t body = 1 + payload_len + (cipher_length_is_aad(c) ? 0 : 4);
	size_t pad = bs - body % bs;
	if (pad < 4)
		pad += bs;
	return pad;
}

int pkt_send(pkt_conn *pc, const uint8_t *payload, size_t len)
{
	if (len > PAYLOAD_MAX)
		return -1;
	const cipher_ctx *c = &pc->tx.ctx;
	size_t pad = padding_for(c, len);
	size_t n = 4 + 1 + len + pad, tag = cipher_tag_len(c);
	uint8_t buf[4 + 1 + PAYLOAD_MAX + 64 + CIPHER_TAG_MAX];

	poke_u32(buf, (uint32_t)(n - 4));
	buf[4] = (uint8_t)pad;
	memcpy(buf + 5, payload, len);
	randombytes_buf(buf + 5 + len, pad);
	cipher_seal(c, pc->tx.seq, buf, n, buf + n);
	pc->tx.seq++;
	return write_full(pc->fd, buf, n + tag);
}

int pkt_recv(pkt_conn *pc, wbuf *payload)
{
	const cipher_ctx *c = &pc->rx.ctx;
	size_t tag = cipher_tag_len(c), bs = cipher_block_size(c);
	uint8_t head[4];

	if (read_full(pc->fd, head, 4) < 0)
		return -1;
	uint32_t plen = cipher_peek_length(c, pc->rx.seq, head);
	size_t aligned = plen + (cipher_length_is_aad(c) ? 0 : 4);
	if (plen < 5 || plen > PACKET_MAX || aligned % bs != 0)
		return -1;

	wbuf_reset(payload);
	uint8_t *pkt = wbuf_reserve(payload, 4 + plen + tag);
	if (!pkt)
		return -1;
	memcpy(pkt, head, 4);
	if (read_full(pc->fd, pkt + 4, plen + tag) < 0)
		return -1;
	if (cipher_open(c, pc->rx.seq, pkt, 4 + plen, pkt + 4 + plen) < 0)
		return -1;
	pc->rx.seq++;

	uint8_t pad = pkt[4];
	if (pad < 4 || (size_t)pad + 1 > plen)
		return -1;
	size_t len = plen - 1 - pad;
	memmove(pkt, pkt + 5, len);
	payload->len = len;
	return 0;
}
