/* Binary packet protocol (RFC 4253 section 6).
 *
 *   uint32 packet_length; byte padding_length; payload; padding; MAC/tag
 *
 * Each direction has its own cipher state and 32-bit sequence number,
 * which counts every packet and wraps silently. */
#ifndef TUNNEL_PACKET_H
#define TUNNEL_PACKET_H

#include <stdint.h>

#include "buf.h"
#include "cipher.h"

#define PACKET_MAX 262144 /* packet_length limit we accept (>= 35000) */
#define PAYLOAD_MAX 32768 /* payload size we send */

typedef struct {
	cipher_ctx ctx;
	uint32_t seq;
} pkt_dir;

typedef struct {
	int fd;
	pkt_dir tx, rx;
} pkt_conn;

void pkt_init(pkt_conn *pc, int fd);
int pkt_send(pkt_conn *pc, const uint8_t *payload, size_t len);
/* Replaces *payload with the next packet's payload. */
int pkt_recv(pkt_conn *pc, wbuf *payload);

#endif
