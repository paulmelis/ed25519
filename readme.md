Ed25519
=======

Note: this is a fork of the Ed25519 implementation available at 
https://github.com/orlp/ed25519. 

That original implementation is 
by Orson Peters <orsonpeters@gmail.com>.

This fork, by Paul Melis <paul.melis@gmail.com>, has additional features,
see below.

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

Additional features
-------------------

Compared to the original code at https://github.com/orlp/ed25519 this
Ed25519 implementation contains a Python 3 module (`ed25519`) that wraps the
C routines for creating key pairs, signing and verifying messages. 

The `ed25519` Python module also has an additional option to use a custom 
hash function in place of the default SHA-512. See `ed25519.custom_hash_function()`.

There's also two extra utility routines `ed25519_privkey_from_ref10` and `ed25519_get_pubkey`,
including Python wrappers. See the description of the C API below.

Limitations:

- Currently, C routines `ed25519_add_scalar` and `ed25519_key_exchange` are
not available from Python, but this would not be much work to add.
- The Python module is only compatible with Python 3.x


Performance
-----------

On a Windows machine with an Intel Pentium B970 @ 2.3GHz I got the following
speeds (running on only one a single core):

    Seed generation: 64us (15625 per second)
    Key generation: 88us (11364 per second)
    Message signing (short message): 87us (11494 per second)
    Message verifying (short message): 228us (4386 per second)
    Scalar addition: 100us (10000 per second)
    Key exchange: 220us (4545 per second)

The speeds on other machines may vary. Sign/verify times will be higher with
longer messages. The implementation significantly benefits from 64 bit
architectures, if possible compile as 64 bit.


Usage
-----

Simply add all .c and .h files in the `src/` folder to your project and include
`ed25519.h` in any file you want to use the API. If you prefer to use a shared
library, only copy `ed25519.h` and define `ED25519_DLL` before importing. A
windows DLL is pre-built.

There are no defined types for seeds, private keys, public keys, shared secrets
or signatures. Instead simple `unsigned char` buffers are used with the
following sizes:

```c
unsigned char seed[32];
unsigned char signature[64];
unsigned char public_key[32];
unsigned char private_key[64];
unsigned char scalar[32];
unsigned char shared_secret[32];
```

API
---

```c
int ed25519_create_seed(unsigned char *seed);
```

Creates a 32 byte random seed in `seed` for key generation. `seed` must be a
writable 32 byte buffer. Returns 0 on success, and nonzero on failure.

```c
void ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key,
                            const unsigned char *seed);
```

Creates a new key pair from the given seed. `public_key` must be a writable 32
byte buffer, `private_key` must be a writable 64 byte buffer and `seed` must be
a 32 byte buffer.

```c
void ed25519_get_pubkey(unsigned char *public_key, const unsigned char *private_key);
```

Derives public key from the given private key. `public_key` must be 
a writable 32 byte buffer, `private_key` must be a 64 byte buffer with 
a valid private key.


```c
void ed25519_sign(unsigned char *signature,
                  const unsigned char *message, size_t message_len,
                  const unsigned char *public_key, const unsigned char *private_key);
```

Creates a signature of the given message with the given key pair. `signature`
must be a writable 64 byte buffer. `message` must have at least `message_len`
bytes to be read. 

```c
int ed25519_verify(const unsigned char *signature,
                   const unsigned char *message, size_t message_len,
                   const unsigned char *public_key);
```

Verifies the signature on the given message using `public_key`. `signature`
must be a readable 64 byte buffer. `message` must have at least `message_len`
bytes to be read. Returns 1 if the signature matches, 0 otherwise.

```c
void ed25519_add_scalar(unsigned char *public_key, unsigned char *private_key,
                        const unsigned char *scalar);
```

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

Performs a key exchange on the given public key and private key, producing a
shared secret. It is recommended to hash the shared secret before using it.
`shared_secret` must be a 32 byte writable buffer where the shared secret will
be stored.

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

From https://github.com/orlp/ed25519/issues/1

> There are different ways to store a Ed25519 private key. The seed gets hashed to get the private key, and then the private key gets multiplied by the Ed25519 curve basepoint to get the public key. You can store the seed and hash it everytime you need the private key, or just store the result of the hash. My library does the latter, as this saves a bit of performance on every operation. This means that it's impossible to get the seed back from the private or public key.
> 
> Also interesting is that Ed25519 also requires the public key while signing. Some libraries hide this by concatenating the public key and the private key/seed and calling that result the private key. I don't, and require you to pass both the public key and private key to the sign operation.
> 
> It's impossible to get the seed from the private key. To turn a private key (which is the hashed seed) into a public key, look into `ed25519_create_keypair` and remove the hashing code.

From https://github.com/orlp/ed25519/issues/10

> `ed25519_sign` is not significantly different from SUPERCOP's ref10, I simply have a different representation of the private key.
>
> ref10 stores the private key by storing the seed (32 bytes) and public key (32 bytes) as the 'private key'.
>
> I instead straight up store the hashed seed (64 bytes) as the private key to not have to re-hash the seed on every sign operation.
>
> So if you simply use the 64 bytes from the ref10 'private key' as the private key in this library you will end up with incorrect results.
>
> If you wish to convert a ref10 private key to a private key for this library you can use:

```
void ref10_to_lib(unsigned char *private_key, const unsigned char *ref10_private_key) {
    sha512(ref10_private_key, 32, private_key);
    private_key[0] &= 248;
    private_key[31] &= 63;
    private_key[31] |= 64;
}
```
