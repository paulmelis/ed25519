#!/usr/bin/env python
import ed25519

message = b'Hello world!'

pubkey, privkey = ed25519.create_keypair(b'abcdefghijklmnopqrstuvwxyz789012')

signature = ed25519.sign(message, pubkey, privkey)
print(signature)
assert len(signature) == 64

res = ed25519.verify(signature, message, pubkey)
assert res

signature = bytes([255 - signature[0]]) + signature[1:]
res = ed25519.verify(signature, message, pubkey)
assert not res

