# Tunnel

A from-scratch SSH-2 client (`tunnel`) and server (`tunneld`) in C,
layered the way the RFCs are: wire encoding, transport, user
authentication, connection. It interoperates with OpenSSH in both
directions. libsodium supplies the cryptographic primitives. All protocol
logic is implemented here.

## Layout

| File | RFC / spec | Concept |
|------|------------|---------|
| `src/buf.{h,c}` | RFC 4251 §5 | byte, uint32, boolean, string, mpint, name-list on bounded buffers |
| `src/io.{h,c}` | — | full-length blocking read/write |
| `src/ssh_msg.h` | RFC 4250 §4 | message numbers, reason codes |
| `src/version.{h,c}` | RFC 4253 §4.2 | identification string exchange |
| `src/cipher.{h,c}` | PROTOCOL.chacha20poly1305 | `none` and `chacha20-poly1305@openssh.com` |
| `src/packet.{h,c}` | RFC 4253 §6 | binary packet protocol, padding, sequence numbers |
| `src/kexinit.{h,c}` | RFC 4253 §7.1 | KEXINIT encoding and algorithm negotiation |
| `src/kex.{h,c}` | RFC 8731, RFC 5656 §4 | curve25519-sha256 shared secret and exchange hash H |
| `src/kdf.{h,c}` | RFC 4253 §7.2 | key derivation from K, H and session id |
| `src/sshkey.{h,c}` | RFC 8709, PROTOCOL.key | ssh-ed25519 blobs, signatures, key files |
| `src/knownhosts.{h,c}` | OpenSSH `known_hosts` | client host key store |
| `src/authkeys.{h,c}` | OpenSSH `authorized_keys` | server publickey allow-list |
| `src/transport.{h,c}` | RFC 4253 §7–9, strict KEX | the handshake driver and the filtered message stream |
| `src/userauth.h`, `userauth_client.c`, `userauth_server.c` | RFC 4252 | service request, none, publickey, password |
| `src/channel.{h,c}` | RFC 4254 §5 | channel ids, windows, EOF/CLOSE |
| `src/session.{h,c}` | RFC 4254 §6 | server session: pty-req, env, shell/exec via forkpty or pipes |
| `src/server_conn.{h,c}` | RFC 4254 | server event loop |
| `src/client_conn.{h,c}` | RFC 4254 | client session relay |
| `src/server_main.c`, `src/client_main.c` | — | command-line entry points |
| `tests/test_*.c` | — | unit tests (`tests/check.h` is the harness) |
| `tests/e2e.sh` | — | end-to-end tests against OpenSSH `ssh` and `sshd` |
| `tests/fixtures/` | RFC 8032 §7.1 | Ed25519 test key in OpenSSH format, plus its generator |

## Build

You need a C11 compiler, `make`, libsodium (headers and library), and
libutil (`forkpty`, which glibc ships).

    make            # builds ./tunnel and ./tunneld
    make unit       # unit tests
    make e2e        # end-to-end tests (uses ssh-keygen, plus ssh/sshd if present)
    make test       # both

## Run

The server runs as the invoking user, and only that user can log in.
Pass it a host key in OpenSSH ed25519 format with no passphrase:

    ssh-keygen -t ed25519 -N '' -f /tmp/hk
    ./tunneld -k /tmp/hk -p 2222 -a /tmp/authorized_keys [-P /tmp/password_file]

Client:

    ./tunnel -p 2222 -i /tmp/id_ed25519 -o /tmp/known_hosts 127.0.0.1 'uname -a'
    TUNNEL_PASSWORD=secret ./tunnel -p 2222 -o /tmp/known_hosts 127.0.0.1
    ./tunnel -t ...        # force a pty;  -T disables it
    ./tunnel -E LANG ...   # forward an environment variable
    ./tunnel -S ...        # refuse unknown host keys (default: accept-new)

### Against OpenSSH

Connect to `tunneld` with OpenSSH's client. These options keep it away
from your own `~/.ssh` and config:

    ssh -F /dev/null -o UserKnownHostsFile=/tmp/kh -o StrictHostKeyChecking=accept-new \
        -o IdentitiesOnly=yes -i /tmp/id_ed25519 -p 2222 127.0.0.1 'echo hi'

OpenSSH 10 prints a warning that the key exchange is not post-quantum.
That is expected, because only curve25519-sha256 is implemented.

To connect with `tunnel` to an unprivileged `sshd`, copy the
configuration from `tests/e2e.sh`: `UsePAM no`, `StrictModes no`,
`PidFile none`, a temporary `HostKey`, and a temporary `AuthorizedKeysFile`.

## Scope

- Implemented: curve25519-sha256 (and its `@libssh.org` alias), ssh-ed25519,
  chacha20-poly1305@openssh.com, compression `none`, strict KEX (the Terrapin
  mitigation), re-exchange when the peer starts it, and userauth with none,
  publickey and password. Sessions support pty-req, env (LANG and LC_* only),
  shell, exec, window-change, exit-status/exit-signal, and EOF/CLOSE.
- Not implemented: re-exchange started by us, other ciphers, MACs, KEX
  methods and host key types, encrypted private keys, port forwarding,
  agent and X11 forwarding, terminal mode application, and privilege
  separation.
