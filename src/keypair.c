#include "ed25519.h"
#include "hash.h"
#include "ge.h"


void ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed) {
    ge_p3 A;

    hash(seed, 32, private_key);
    private_key[0] &= 248;
    private_key[31] &= 63;
    private_key[31] |= 64;

    ge_scalarmult_base(&A, private_key);
    ge_p3_tobytes(public_key, &A);
}


void ed25519_get_pubkey(unsigned char *public_key, const unsigned char *private_key) {
    ge_p3 A;

    ge_scalarmult_base(&A, private_key);
    ge_p3_tobytes(public_key, &A);
}

void ed25519_privkey_from_ref10(unsigned char *private_key, const unsigned char *ref10_private_key) {
    hash(ref10_private_key, 32, private_key);
    private_key[0] &= 248;
    private_key[31] &= 63;
    private_key[31] |= 64;
}