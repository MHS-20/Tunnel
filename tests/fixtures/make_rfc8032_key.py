#!/usr/bin/env python3
"""Packs the RFC 8032 section 7.1 TEST 1 Ed25519 key into the OpenSSH
private key format (PROTOCOL.key, unencrypted). The .pub file is then
produced by `ssh-keygen -y`, which independently validates the encoding."""
import base64, struct

seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

def s(b): return struct.pack(">I", len(b)) + b

blob = s(b"ssh-ed25519") + s(pk)
priv = struct.pack(">II", 0x01020304, 0x01020304) + s(b"ssh-ed25519") + s(pk) + s(seed + pk) + s(b"rfc8032-test1")
priv += bytes(range(1, 1 + (-len(priv)) % 8))
body = b"openssh-key-v1\0" + s(b"none") + s(b"none") + s(b"") + struct.pack(">I", 1) + s(blob) + s(priv)
b64 = base64.b64encode(body).decode()
print("-----BEGIN OPENSSH PRIVATE KEY-----")
for i in range(0, len(b64), 70): print(b64[i:i+70])
print("-----END OPENSSH PRIVATE KEY-----")
