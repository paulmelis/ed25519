#include "ed25519.h"
#include "hash.h"
#include "ge.h"
#include "sc.h"


void ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key) {
    void *hash_context;
    unsigned char hram[64];
    unsigned char r[64];
    ge_p3 R;

    hash_context = hash_create_context();
    
    hash_init(hash_context);
    hash_update(hash_context, private_key + 32, 32);
    hash_update(hash_context, message, message_len);
    hash_final(hash_context, r);

    sc_reduce(r);
    ge_scalarmult_base(&R, r);
    ge_p3_tobytes(signature, &R);

    hash_init(hash_context);
    hash_update(hash_context, signature, 32);
    hash_update(hash_context, public_key, 32);
    hash_update(hash_context, message, message_len);
    hash_final(hash_context, hram);

    sc_reduce(hram);
    sc_muladd(signature + 32, hram, private_key, r);
    
    hash_free_context(hash_context);
}
