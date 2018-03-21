Ed25519
=======

Note: this is a fork of the Ed25519 implementation available at
https://github.com/orlp/ed25519.

That original implementation is by Orson Peters (orsonpeters@gmail.com).
Many thanks to him for creating such a comprehensive library and
making it available as open source.

This fork, by Paul Melis (paul.melis@gmail.com), has additional features:

* A Python 3 module, `ed25519`, that wraps the C routines for creating key pairs, signing and verifying messages
* The `ed25519` Python module also has an additional option to use a custom
  hash function in place of the default SHA-512. See `ed25519.custom_hash_function()`.
* There's also two extra utility routines `ed25519_privkey_from_ref10` and `ed25519_get_pubkey`,
  also available from Python. See the description of the C API below.
* The Python routines can be called in a multi-threading setting, as the GIL
is released around the calls to the underlying C API calls. This even holds
for the case of a custom hash function defined in Python. This gives quite a
nice speedup on a synthetic benchmark of checking the signature of a 64-byte
message (at least for up to 4 threads):

    | Threads | Performance | Speedup |
    | ------- | ----------- | ------- |
    | 1 | 100000 jobs in 9.419 seconds | 1.00x |
    | 2 | 100000 jobs in 4.978 seconds | 1.89x |
    | 4 | 100000 jobs in 2.501 seconds | 3.77x |
    | 8 | 100000 jobs in 2.356 seconds | 4.00x |

Limitations:

- Currently, C routine `ed25519_add_scalar` is not available from Python, but this
  would not be much work to add.
- The Python module is only compatible with Python 3.x

Original description
--------------------

This is a portable implementation of [Ed25519](http://ed25519.cr.yp.to/) based
on the SUPERCOP "ref10" implementation. Additionally there is key exchanging
and scalar addition included to further aid building a PKI using Ed25519. All
code is licensed under the permissive zlib license.

All code is pure ANSI C without any dependencies, except for the random seed
generation which uses standard OS cryptography APIs (`CryptGenRandom` on
Windows, `/dev/urandom` on nix). If you wish to be entirely portable define
`ED25519_NO_SEED`. This disables the `ed25519_create_seed` function, so if your
application requires key generation you must supply your own seeding function
(which is simply a 256 bit (32 byte) cryptographic random number generator).

Performance
-----------

On a Linux machine with an Intel(R) Core(TM) i5-4460 CPU @ 3.20GHz:

| Call | Performance |
| ---- | ----------- |
| ed25519_create_seed | 50113.256 per second |
| ed25519_create_keypair | 23481.813 per second |
| ed25519_sign (short message) | 23064.912 per second |
| ed25519_verify (short message) | 9011.514 per second |
| ed25519_add_scalar | 23382.679 per second |
| ed25519_key_exchange | 9151.911 per second |

When used from Python the speeds are only slightly lower:

| Call | Performance |
| ---- | ----------- |
| create_seed | 49252.795 per second |
| create_keypair | 22812.513 per second |
| sign | 22501.740 per second |
| verify | 8674.004 per second |
| key_exchange | 9058.414 per second |

The speeds on other machines will vary, of course.
Sign/verify times will be higher with longer messages.

The implementation significantly benefits from 64 bit
architectures, if possible compile as 64 bit.


Usage
-----

CMake files are provided to build a static library, `ed25519.a`. The `WITH_PYTHON`
option (set to ON by default) enables building of the Python module.

An alternative is to simply add all .c and .h files in the `src/` folder (except
`pyapi.c` and `pyapi.h`) to your project and include `ed25519.h` in any file you
want to use the API.

For the C API there are no defined types for seeds, private keys, public keys, shared secrets or signatures. Instead simple `unsigned char` buffers are used with the
following sizes:

```c
unsigned char seed[32];
unsigned char signature[64];
unsigned char public_key[32];
unsigned char private_key[64];
unsigned char scalar[32];
unsigned char shared_secret[32];
```

In the Python API `bytes` objects are used for these values, with the same lengths.

API
---

This documents both the C and Python APIs. Remarks about writable buffer
sizes do not apply to the Python API.

```c
int ed25519_create_seed(unsigned char *seed);
```

```python
ed25519.create_seed() # -> seed
```

Creates a 32 byte random seed in `seed` for key generation. C only: `seed` must be a
writable 32 byte buffer. Returns 0 on success, and nonzero on failure.

```c
void ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key,
                            const unsigned char *seed);
```

```python
ed25519.create_keypair(seed) # -> public_key, private_key
```

Creates a new key pair from the given seed. C only: `public_key` must be a writable 32
byte buffer, `private_key` must be a writable 64 byte buffer. `seed` must be
a 32 byte buffer.

```c
void ed25519_get_pubkey(unsigned char *public_key, const unsigned char *private_key);
```

```python
ed25519.get_pubkey(private_key) # -> public_key
```


Derives public key from the given private key. C only: `public_key` must be
a writable 32 byte buffer, `private_key` must be a 64 byte buffer with
a valid private key.


```c
void ed25519_sign(unsigned char *signature,
                  const unsigned char *message, size_t message_len,
                  const unsigned char *public_key, const unsigned char *private_key);
```

```python
ed25519.sign(message, public_key, private_key) # -> signature
```

Creates a signature of the given message with the given key pair. C only: `signature`
must be a writable 64 byte buffer, `message` must have at least `message_len`
bytes to be read.

```c
int ed25519_verify(const unsigned char *signature,
                   const unsigned char *message, size_t message_len,
                   const unsigned char *public_key);
```

```python
ed25519.verify(signature, message, public_key) # -> bool
```

Verifies the signature on the given message using `public_key`. `signature`
must be a readable 64 byte buffer. C only: `message` must have at least `message_len`
bytes to be read. C only: returns 1 if the signature matches, 0 otherwise. Python:
return `True` if the signature matches, `False` otherwise.

```c
void ed25519_add_scalar(unsigned char *public_key, unsigned char *private_key,
                        const unsigned char *scalar);
```

(Not available from Python)

Adds `scalar` to the given key pair where scalar is a 32 byte buffer (possibly
generated with `ed25519_create_seed`), generating a new key pair. You can
calculate the public key sum without knowing the private key and vice versa by
passing in `NULL` for the key you don't know. This is useful for enforcing
randomness on a key pair by a third party while only knowing the public key,
among other things.  Warning: the last bit of the scalar is ignored - if
comparing scalars make sure to clear it with `scalar[31] &= 127`.


```c
void ed25519_key_exchange(unsigned char *shared_secret,
                          const unsigned char *public_key, const unsigned char *private_key);
```

```python
ed25519.key_exchange(public_key, private_key) # -> shared_secret
```

Performs a key exchange on the given public key and private key, producing a
shared secret. It is recommended to hash the shared secret before using it.
C only: `shared_secret` must be a 32 byte writable buffer where the shared secret will
be stored.

```c
void ed25519_privkey_from_ref10(unsigned char *private_key, const unsigned char *ref10_private_key);
```

```python
ed25519.privkey_from_ref10(ref10_private) # -> private_key
```

Convert a private key stored as the seed (32 bytes) plus public key (32 bytes), such as
used by SUPERCOP's ref10 implementation, into a private key usable by this library.


Examples
-------

```c
unsigned char seed[32], public_key[32], private_key[64], signature[64];
unsigned char other_public_key[32], other_private_key[64], shared_secret[32];
const unsigned char message[] = "TEST MESSAGE";

/* create a random seed, and a key pair out of that seed */
if (ed25519_create_seed(seed)) {
    printf("error while generating seed\n");
    exit(1);
}

ed25519_create_keypair(public_key, private_key, seed);

/* create signature on the message with the key pair */
ed25519_sign(signature, message, strlen(message), public_key, private_key);

/* verify the signature */
if (ed25519_verify(signature, message, strlen(message), public_key)) {
    printf("valid signature\n");
} else {
    printf("invalid signature\n");
}

/* create a dummy keypair to use for a key exchange, normally you'd only have
the public key and receive it through some communication channel */
if (ed25519_create_seed(seed)) {
    printf("error while generating seed\n");
    exit(1);
}

ed25519_create_keypair(other_public_key, other_private_key, seed);

/* do a key exchange with other_public_key */
ed25519_key_exchange(shared_secret, other_public_key, private_key);

/*
    the magic here is that ed25519_key_exchange(shared_secret, public_key,
    other_private_key); would result in the same shared_secret
*/

```

```python
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
```


License
-------

All code is released under the zlib license. See license.txt for details.

The additional code by Paul Melis is covered by the same license.


Compatibility with other Ed25519 implementations
------------------------------------------------

(Description based on [these](https://github.com/orlp/ed25519/issues/1)
[issues](https://github.com/orlp/ed25519/issues/10))

There are different ways to store a Ed25519 private key. The seed
gets hashed to get the private key and then the private key gets
multiplied by the Ed25519 curve basepoint to get the public key.
One can store the seed and hash it everytime you need the private
key, or just store the result of the hash.

This library does the latter (storing the hashed seed), as this saves
a bit of performance on every operation. This means that it's
impossible to get the seed back from the private or public key.

Also interesting is that Ed25519 requires the public key while
signing. Some libraries hide this by concatenating the public key and
the private key/seed and calling that result the "private key". Here
we don't take that approach and require you to pass both the public key
and private key to the sign operation.

Specifically, for [SUPERCOP's ref10](https://bench.cr.yp.to/supercop.html),
it uses the above representation of the private key. The ref10 implementation
stores the private key by storing the seed (32 bytes) and public key (32 bytes)
as the 'private key'. So if you simply use the 64 bytes from the ref10 'private key'
as the private key in this library you will end up with incorrect results.
If you wish to convert a ref10 private key to a private key for this library you can
use `ed25519_privkey_from_ref10`.
