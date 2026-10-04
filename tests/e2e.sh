#!/usr/bin/env bash
# End-to-end tests: tunneld with a throwaway host key on a high localhost
# port, exercised by our client and (if installed) OpenSSH's ssh; plus our
# client against an unprivileged OpenSSH sshd. Never touches ~/.ssh.
set -u
cd "$(dirname "$0")/.."

T=$(mktemp -d "${TMPDIR:-/tmp}/tunnel-e2e.XXXXXX")
PORT=$((20000 + RANDOM % 20000))
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; rm -rf "$T"; }
trap cleanup EXIT

pass=0 fail=0 skip=0
ok()   { echo "PASS  $1"; pass=$((pass + 1)); }
bad()  { echo "FAIL  $1"; fail=$((fail + 1)); }
skp()  { echo "SKIP  $1"; skip=$((skip + 1)); }
expect() { # name, want, got
	if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want '$2', got '$3')"; fi
}

ssh-keygen -q -t ed25519 -N '' -C host -f "$T/host"
ssh-keygen -q -t ed25519 -N '' -C user -f "$T/user"
cp "$T/user.pub" "$T/authorized_keys"
echo 'correct horse' > "$T/password"

./tunneld -k "$T/host" -p "$PORT" -a "$T/authorized_keys" -P "$T/password" 2>"$T/server.log" &
PIDS+=($!)
for _ in $(seq 50); do (echo >/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break; sleep 0.1; done

TUN=(./tunnel -o "$T/known_hosts" -p "$PORT")

# --- our client ------------------------------------------------------------
out=$("${TUN[@]}" -i "$T/user" 127.0.0.1 'echo hello from exec' 2>/dev/null)
expect "tunnel: publickey + exec" "hello from exec" "$out"
grep -q "^\[127.0.0.1\]:$PORT ssh-ed25519 " "$T/known_hosts" && ok "tunnel: known_hosts recorded" \
	|| bad "tunnel: known_hosts recorded"

"${TUN[@]}" -S -i "$T/user" 127.0.0.1 'exit 7' 2>/dev/null
expect "tunnel: exit-status propagated (strict known host)" 7 $?

err=$("${TUN[@]}" -i "$T/user" 127.0.0.1 'echo oops >&2' 2>&1 >/dev/null)
expect "tunnel: stderr via extended data" "oops" "$err"

out=$(TUNNEL_PASSWORD='correct horse' "${TUN[@]}" 127.0.0.1 'echo pw' 2>/dev/null)
expect "tunnel: password auth" "pw" "$out"
TUNNEL_PASSWORD=wrong "${TUN[@]}" 127.0.0.1 true 2>/dev/null
expect "tunnel: wrong password rejected" 255 $?

out=$(LC_TUNNEL=xyz "${TUN[@]}" -E LC_TUNNEL -i "$T/user" 127.0.0.1 'echo $LC_TUNNEL' 2>/dev/null)
expect "tunnel: env request" "xyz" "$out"

head -c 3000000 /dev/urandom > "$T/blob"
want=$(sha256sum < "$T/blob" | cut -d' ' -f1)
got=$("${TUN[@]}" -i "$T/user" 127.0.0.1 sha256sum < "$T/blob" 2>/dev/null | cut -d' ' -f1)
expect "tunnel: 3 MB upload through window" "$want" "$got"
got=$("${TUN[@]}" -i "$T/user" 127.0.0.1 "cat '$T/blob'" 2>/dev/null | sha256sum | cut -d' ' -f1)
expect "tunnel: 3 MB download through window" "$want" "$got"

out=$("${TUN[@]}" -t -i "$T/user" 127.0.0.1 'test -t 0 && echo tty' 2>/dev/null </dev/null | tr -d '\r')
expect "tunnel: pty-req" "tty" "$out"

# A different key for the same host:port must be refused.
sed "s|ssh-ed25519 .*|$(cut -d' ' -f1,2 "$T/user.pub")|" "$T/known_hosts" > "$T/known_hosts.bad"
./tunnel -o "$T/known_hosts.bad" -p "$PORT" -i "$T/user" 127.0.0.1 true 2>/dev/null
expect "tunnel: host key mismatch refused" 255 $?

# --- OpenSSH client against tunneld --------------------------------------
if command -v ssh >/dev/null; then
	SSH=(ssh -F /dev/null -o UserKnownHostsFile="$T/ssh_known_hosts" -o StrictHostKeyChecking=accept-new
	     -o IdentitiesOnly=yes -o IdentityFile="$T/user" -o BatchMode=yes -o LogLevel=ERROR
	     -p "$PORT" 127.0.0.1)
	out=$("${SSH[@]}" 'echo hello openssh' 2>/dev/null)
	expect "ssh: publickey + exec" "hello openssh" "$out"
	"${SSH[@]}" 'exit 42' 2>/dev/null
	expect "ssh: exit-status" 42 $?
	out=$("${SSH[@]}" -tt 'test -t 0 && echo tty' 2>/dev/null </dev/null | tr -d '\r')
	expect "ssh: pty-req + exec" "tty" "$out"
	got=$("${SSH[@]}" sha256sum < "$T/blob" 2>/dev/null | cut -d' ' -f1)
	expect "ssh: 3 MB upload" "$want" "$got"
	got=$("${SSH[@]}" -o RekeyLimit=256K -v sha256sum < "$T/blob" 2>"$T/rekey.log" | cut -d' ' -f1)
	kexinits=$(grep -c "SSH2_MSG_KEXINIT sent" "$T/rekey.log")
	if [ "$got" = "$want" ] && [ "$kexinits" -gt 1 ]; then
		ok "ssh: client-initiated rekey ($kexinits key exchanges)"
	else
		bad "ssh: client-initiated rekey (hash ok? $([ "$got" = "$want" ] && echo y || echo n), kexinits=$kexinits)"
	fi
else
	skp "ssh not installed"
fi

# --- tunnel against an unprivileged OpenSSH sshd ------------------------
SSHD=$(command -v sshd || true)
if [ -n "$SSHD" ]; then
	SPORT=$((PORT + 1))
	cat > "$T/sshd_config" <<CFG
Port $SPORT
ListenAddress 127.0.0.1
HostKey $T/host
AuthorizedKeysFile $T/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
PidFile none
CFG
	"$SSHD" -D -e -f "$T/sshd_config" 2>"$T/sshd.log" &
	PIDS+=($!)
	for _ in $(seq 50); do (echo >/dev/tcp/127.0.0.1/$SPORT) 2>/dev/null && break; sleep 0.1; done
	out=$(./tunnel -o "$T/known_hosts2" -p "$SPORT" -i "$T/user" 127.0.0.1 'echo hello sshd; exit 5' 2>"$T/client.log")
	rc=$?
	if [ "$out" = "hello sshd" ] && [ $rc = 5 ]; then
		ok "tunnel -> OpenSSH sshd: exec + exit-status"
	elif grep -q "cannot connect" "$T/client.log"; then
		skp "sshd could not start unprivileged ($(tail -1 "$T/sshd.log"))"
	else
		bad "tunnel -> OpenSSH sshd (out='$out' rc=$rc): $(cat "$T/client.log")"
	fi
else
	skp "sshd not installed"
fi

echo "e2e: $pass passed, $fail failed, $skip skipped"
[ "$fail" = 0 ]
