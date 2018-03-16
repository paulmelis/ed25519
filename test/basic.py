#!/usr/bin/env python
import ed25519

message = b'Hello world!'
seed = b'abcdefghijklmnopqrstuvwxyz789012'

pubkey, privkey = ed25519.create_keypair(seed)

derived_pubkey = ed25519.get_pubkey(privkey)
assert derived_pubkey == pubkey

signature = ed25519.sign(message, pubkey, privkey)
assert len(signature) == 64

res = ed25519.verify(signature, message, pubkey)
assert res

signature = bytes([255 - signature[0]]) + signature[1:]
res = ed25519.verify(signature, message, pubkey)
assert not res
