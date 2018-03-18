#!/usr/bin/env python
import ed25519

s1 = ed25519.create_seed()
s2 = ed25519.create_seed()

pub1, priv1 = ed25519.create_keypair(s1)
pub2, priv2 = ed25519.create_keypair(s2)

secret1 = ed25519.key_exchange(pub2, priv1)
secret2 = ed25519.key_exchange(pub1, priv2)

print(secret1.hex())
print(secret2.hex())

assert secret1 == secret2
