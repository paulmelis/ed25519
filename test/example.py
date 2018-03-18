#!/usr/bin/env python3
import time
from ed25519 import *

message = b'Hello, world!'
message_len = len(message)

# create a random seed, and a keypair out of that seed 
seed = create_seed()
public_key, private_key = create_keypair(seed)

# create signature on the message with the keypair 
signature = sign(message, public_key, private_key)

# verify the signature 
if verify(signature, message, public_key):
    print('valid signature')
else:
    print('invalid signature')

"""
# create scalar and add it to the keypair 
create_seed(scalar)
add_scalar(public_key, private_key, scalar)

# create signature with the new keypair 
sign(signature, message, message_len, public_key, private_key)

# verify the signature with the new keypair 
if (verify(signature, message, message_len, public_key)) {
    print('valid signature')
} else {
    print('invalid signature')
}
"""

# make a slight adjustment and verify again 
signature = signature[:44] + bytes([signature[44] ^ 0x10]) + signature[45:]
if verify(signature, message, public_key):
    print('did not detect signature change')
else:
    print('correctly detected signature change')

# generate two keypairs for testing key exchange 
seed = create_seed()
public_key, private_key = create_keypair(seed)
seed = create_seed()
other_public_key, other_private_key = create_keypair(seed)

# create two shared secrets - from both perspectives - and check if they're equal 
shared_secret = key_exchange(other_public_key, private_key)
other_shared_secret = key_exchange(public_key, other_private_key)

if shared_secret != other_shared_secret:
    print('key exchange was incorrect')
else:
    print('key exchange was correct')
    
# test performance 

N = 20000

start = time.time()
for i in range(N):
    seed = create_seed()
end = time.time()
tdiff = end - start
print('create_seed: %.3f per second'% (N/tdiff))

start = time.time()
for i in range(N):
    public_key, private_key = create_keypair(seed)
end = time.time()
tdiff = end - start
print('create_keypair: %.3f per second'% (N/tdiff))

start = time.time()
for i in range(N):
    signature = sign(message, public_key, private_key)
end = time.time()
tdiff = end - start
print('sign: %.3f per second'% (N/tdiff))

start = time.time()
for i in range(N):
    verify(signature, message, public_key)
end = time.time()
tdiff = end - start
print('verify: %.3f per second'% (N/tdiff))

"""
print('testing keypair scalar addition performance: ',)
start = time.time()
for i in range(N):
    add_scalar(public_key, private_key, scalar)
end = time.time()
tdiff = end - start
print('add_scalar: %.3f per second'% (N/tdiff))

print('testing public key scalar addition performance: ',)
start = time.time()
for i in range(N):
    add_scalar(public_key, NULL, scalar)
end = time.time()
tdiff = end - start
print('add_scalar: %.3f per second'% (N/tdiff))
"""

start = time.time()
for i in range(N):
    shared_secret = key_exchange(other_public_key, private_key)
end = time.time()
tdiff = end - start
print('key_exchange: %.3f per second'% (N/tdiff))

