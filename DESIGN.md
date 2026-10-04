# Design

## Crypto library: libsodium

The only cipher is `chacha20-poly1305@openssh.com`, and it is built from
the *original* ChaCha20 with a 64-bit nonce and a 64-bit block counter.
libsodium exposes exactly that primitive as
`crypto_stream_chacha20_xor_ic(c, m, len, nonce8, counter, key)`, together
with Poly1305 (`crypto_onetimeauth_poly1305`), X25519 (`crypto_scalarmult`,
which already rejects the all-zero shared secret RFC 8731 §3 requires us to
refuse), Ed25519 with OpenSSH's 64-byte `seed || pk` secret-key layout
(`crypto_sign_detached`), SHA-256, base64, constant-time compare and secure
zeroing. With OpenSSL the code would need the IETF ChaCha20 variant and a
hand-built 16-byte IV (counter || nonce), EVP_MAC for Poly1305, and
EVP_PKEY wrappers for the curve operations. That is more plumbing and adds
nothing to the protocol logic. libsodium has no AES-CTR, so aes128-ctr and
hmac-sha2-256 were left out. Because the only cipher is an AEAD, there is
no separate MAC layer.

libsodium supplies primitives only. Framing, padding, nonce construction
from sequence numbers, the order of the two keys, the exchange hash, key
derivation, and all signature and key encodings are implemented here.

## Layering

Each layer uses only the layer below it:

```
client_main / server_main         CLI, sockets, fork per connection
client_conn / server_conn         RFC 4254 event loops
  channel, session                windows; child processes
userauth_client / userauth_server RFC 4252
transport                         RFC 4253 handshake + message stream
  kexinit, kex, kdf, sshkey       negotiation, curve25519, H, keys, ed25519
packet                            RFC 4253 §6 framing
  cipher                          none / chacha20-poly1305
buf, io, version                  RFC 4251 §5 encoding; raw I/O
```

- `buf` gives both readers and writers a *sticky* error flag. A decoder
  reads every field and then checks `r.err` once, so field access needs no
  error branches, and a read can never go past the slice. Writers grow up
  to `BUF_MAX` (256 KiB). `get_string` returns a zero-copy view into the
  packet.
- `cipher` exposes four operations to `packet`: the block size, the tag
  length, whether the length field is AAD, and peek-length, seal and open.
  This is the seam where AES-CTR plus HMAC would plug in. When the length
  field is AAD (as with chacha), padding aligns `padding_length || payload ||
  padding` and leaves out the length field, which matches OpenSSH's
  `len -= aadlen`.
- `transport` contains the only state machine for key exchange
  (`kex_run`). The same function handles the initial exchange and a
  re-exchange started by the peer: `tr_recv` runs `kex_run` to completion
  when a KEXINIT arrives, then continues. Upper layers never see it.
  Because the loop is single-threaded, nothing is sent between our KEXINIT
  and our NEWKEYS, which is the rule in RFC 4253 §7.1.
- Strict KEX (`kex-strict-*-v00@openssh.com`) is decided once, during the
  initial exchange. It makes any message that is not part of the key
  exchange fatal during that first exchange, and it resets the sequence
  number of each direction to 0 after every NEWKEYS that direction carries.
  OpenSSH 10 always offers strict KEX, so the e2e rekey test exercises this
  path 90 or more times per run.
- Userauth signs `string session_id || request-without-signature`. The
  server checks the signature against the bytes it actually received,
  using the reader offset just before the signature string, so it never
  re-encodes the request.
- `channel` covers only accounting. `local_window` is the credit we have
  granted, and `delivered` counts bytes that have reached their sink (the
  child's stdin, or the client's stdout). The window is refilled with
  WINDOW_ADJUST once `delivered >= CHAN_WINDOW/2`. Data is acknowledged
  only after it reaches its sink, so the window also bounds the per-channel
  buffer. For that reason `CHAN_WINDOW == BUF_MAX`. In an earlier version
  the window (2 MiB) was larger than the buffer, and the e2e upload test
  caught the resulting data loss.
- The server writes to the child's stdin without blocking, using a pending
  buffer and POLLOUT. It reads child output only when the remote window has
  room, so a slow peer stalls the child (backpressure) rather than our
  memory. A child is finished when its stdout and stderr have reached EOF
  (EIO on a pty) *and* it has been reaped. Only then do exit-status, EOF
  and CLOSE go out.

## Simplifications

- One process per connection, single-threaded, and blocking socket writes.
  A packet is read whole once the socket polls readable.
- The server runs as the invoking user. There is no privilege separation
  and no PAM. Password authentication compares against a password file
  given on the command line. The comparison is constant-time, over SHA-256
  digests.
- known_hosts matching accepts only plain `host` and `[host]:port`
  entries. Hashed (`|1|`) and marker (`@`) lines are skipped.
- Re-exchange is answered but never started. A long-lived connection
  therefore depends on the peer to rekey, as OpenSSH does by default.
- The client sends a signed publickey request directly and skips the
  PK_OK query. The server implements PK_OK because OpenSSH queries first.

## Tests

- `test_buf`: the non-negative mpint examples from RFC 4251 §5, the exact
  bytes of each primitive, bounds and sticky errors.
- `test_packet`: the exact on-wire layout of a plaintext packet, round
  trips for every payload length from 0 to 39 and for 32 KiB under both
  ciphers, a check that the AAD length is excluded from padding, and
  rejection of a tampered packet and of a wrong sequence number. It also
  covers parsing of identification lines.
- `test_kexinit`: name-list matching, first-match-by-client-order,
  directional ciphers, wrong-guess detection, no-common-algorithm failure,
  and an encode/decode round trip.
- `test_kex`: the X25519 vectors from RFC 7748 §6.1 in both directions,
  with the expected mpint encoding, and rejection of a low-order point. The
  KDF test checks a three-block (80-byte) derivation against a value
  computed independently with Python `hashlib`, using the same inputs
  (K = mpint `00 f0 11…`, H = 00..1f, session_id = 20..3f, letter `C`).
  No official SSH KDF vector with SHA-256 was available offline.
- `test_sshkey`: the RFC 8032 §7.1 TEST 1 key, packed into OpenSSH format
  by `tests/fixtures/make_rfc8032_key.py`. `ssh-keygen -y` independently
  confirmed the packing and produced the `.pub`. The test checks the RFC
  signature exactly, plus known_hosts add, match and mismatch.
- `tests/e2e.sh`: runs `tunneld` on a random high port with throwaway
  keys, then drives it with `tunnel` and with OpenSSH `ssh`. It covers
  exec, exit codes, stderr, pty, env, password, a host-key mismatch, 3 MB
  in each direction, and an `ssh -o RekeyLimit=256K` transfer, which
  forces repeated re-exchanges. Finally it starts an unprivileged OpenSSH
  `sshd` and connects to it with `tunnel`.

Interop is the real test of the chacha20-poly1305 construction and of the
exchange hash, since there is no official vector for either.

## Upstream references

Protocol details were checked against openssh-portable at commit
`15289cc38956aa74d4947174a68c10ac9ad2157f`. The code here is written
independently and nothing was copied from upstream.

| Module | Upstream file(s) consulted | What was checked |
|--------|----------------------------|------------------|
| `cipher.c` | `PROTOCOL.chacha20poly1305`, `cipher-chachapoly.c:48-49,72-118` | main key = first 32 bytes, header key = last 32; nonce = seqnr as u64; Poly1305 key from block 0; payload at counter 1 |
| `packet.c` | `packet.c:1275-1285` (`ssh_packet_send2_wrapped`) | padding excludes the AAD length field |
| `transport.c` | `PROTOCOL` §1.9, `packet.c:1376-1378,1849-1851`, `kex.c:994-1005` | strict KEX detection and sequence reset after each NEWKEYS |
| `kexinit.c` | `kex.c:1056-1072` | MAC negotiation skipped for AEAD ciphers |
| `kex.c` | `kexc25519.c:59`, `kexgen.c:48` (`kex_gen_hash`) | shared secret encoded as mpint; field order of H |
| `sshkey.c` | `PROTOCOL.key` | private key container layout |
| `channel.c` | `channels.c:2494` (`channel_check_window`), `:3542`, `:3799` | refilling the window at the halfway point; window overflow handling |
