#ifndef ED25519_H
#define ED25519_H

#include <stddef.h>

#if defined(_WIN32)
    #if defined(ED25519_BUILD_DLL)
        #define ED25519_DECLSPEC __declspec(dllexport)
    #elif defined(ED25519_DLL)
        #define ED25519_DECLSPEC __declspec(dllimport)
    #else
        #define ED25519_DECLSPEC
    #endif
#else
    #define ED25519_DECLSPEC
#endif


#ifdef __cplusplus
extern "C" {
#endif

#ifndef ED25519_NO_SEED
// Create a random 32 byte seed
int ED25519_DECLSPEC ed25519_create_seed(unsigned char *seed);
#endif

// Create a public, private key pair from a seed
void ED25519_DECLSPEC ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed);
// Derive the public key from a private key
void ED25519_DECLSPEC ed25519_get_pubkey(unsigned char *public_key, const unsigned char *private_key);
// ref10 stores the private key by storing the seed (32 bytes) and public key (32 bytes) as the 'private key'
void ED25519_DECLSPEC ed25519_privkey_from_ref10(unsigned char *private_key, const unsigned char *ref10_private_key);
// Sign the given message
void ED25519_DECLSPEC ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key);
// Verify the signature for the given message
int ED25519_DECLSPEC ed25519_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key);
void ED25519_DECLSPEC ed25519_add_scalar(unsigned char *public_key, unsigned char *private_key, const unsigned char *scalar);
// Create a shared secret based on the given public and (unrelated) private key
void ED25519_DECLSPEC ed25519_key_exchange(unsigned char *shared_secret, const unsigned char *public_key, const unsigned char *private_key);


#ifdef __cplusplus
}
#endif

#endif
