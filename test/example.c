#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "ed25519.h"

int main() {
    unsigned char public_key[32], private_key[64], seed[32], scalar[32];
    unsigned char other_public_key[32], other_private_key[64];
    unsigned char shared_secret[32], other_shared_secret[32];
    unsigned char signature[64];

    struct timeval start, end;
    int i;
    double tdiff;

    const unsigned char message[] = "Hello, world!";
    const int message_len = strlen((char*) message);

    /* create a random seed, and a keypair out of that seed */
    ed25519_create_seed(seed);
    ed25519_create_keypair(public_key, private_key, seed);

    /* create signature on the message with the keypair */
    ed25519_sign(signature, message, message_len, public_key, private_key);

    /* verify the signature */
    if (ed25519_verify(signature, message, message_len, public_key)) {
        printf("valid signature\n");
    } else {
        printf("invalid signature\n");
    }

    /* create scalar and add it to the keypair */
    ed25519_create_seed(scalar);
    ed25519_add_scalar(public_key, private_key, scalar);

    /* create signature with the new keypair */
    ed25519_sign(signature, message, message_len, public_key, private_key);

    /* verify the signature with the new keypair */
    if (ed25519_verify(signature, message, message_len, public_key)) {
        printf("valid signature\n");
    } else {
        printf("invalid signature\n");
    }

    /* make a slight adjustment and verify again */
    signature[44] ^= 0x10;
    if (ed25519_verify(signature, message, message_len, public_key)) {
        printf("did not detect signature change\n");
    } else {
        printf("correctly detected signature change\n");
    }

    /* generate two keypairs for testing key exchange */
    ed25519_create_seed(seed);
    ed25519_create_keypair(public_key, private_key, seed);
    ed25519_create_seed(seed);
    ed25519_create_keypair(other_public_key, other_private_key, seed);

    /* create two shared secrets - from both perspectives - and check if they're equal */
    ed25519_key_exchange(shared_secret, other_public_key, private_key);
    ed25519_key_exchange(other_shared_secret, public_key, other_private_key);

    for (i = 0; i < 32; ++i) {
        if (shared_secret[i] != other_shared_secret[i]) {
            printf("key exchange was incorrect\n");
            break;
        }
    }

    if (i == 32) {
        printf("key exchange was correct\n");
    }

    /* test performance */
    
    const int N = 20000;
    
    printf("testing seed generation performance: ");
    gettimeofday(&start, NULL);
    for (i = 0; i < N; ++i) {
        ed25519_create_seed(seed);
    }
    gettimeofday(&end, NULL);
    tdiff = end.tv_sec - start.tv_sec + (end.tv_usec - start.tv_usec) / 1000000.0;
    printf("ed25519_create_seed: %.3f per second\n", N/tdiff);

    printf("testing key generation performance: ");
    gettimeofday(&start, NULL);
    for (i = 0; i < N; ++i) {
        ed25519_create_keypair(public_key, private_key, seed);
    }
    gettimeofday(&end, NULL);
    tdiff = end.tv_sec - start.tv_sec + (end.tv_usec - start.tv_usec) / 1000000.0;
    printf("ed25519_create_keypair: %.3f per second\n", N/tdiff);
    
    printf("testing sign performance: ");
    gettimeofday(&start, NULL);
    for (i = 0; i < N; ++i) {
        ed25519_sign(signature, message, message_len, public_key, private_key);
    }
    gettimeofday(&end, NULL);
    tdiff = end.tv_sec - start.tv_sec + (end.tv_usec - start.tv_usec) / 1000000.0;
    printf("ed25519_sign: %.3f per second\n", N/tdiff);

    printf("testing verify performance: ");
    gettimeofday(&start, NULL);
    for (i = 0; i < N; ++i) {
        ed25519_verify(signature, message, message_len, public_key);
    }
    gettimeofday(&end, NULL);
    tdiff = end.tv_sec - start.tv_sec + (end.tv_usec - start.tv_usec) / 1000000.0;
    printf("ed25519_verify: %.3f per second\n", N/tdiff);
    
    printf("testing keypair scalar addition performance: ");
    gettimeofday(&start, NULL);
    for (i = 0; i < N; ++i) {
        ed25519_add_scalar(public_key, private_key, scalar);
    }
    gettimeofday(&end, NULL);
    tdiff = end.tv_sec - start.tv_sec + (end.tv_usec - start.tv_usec) / 1000000.0;
    printf("ed25519_add_scalar: %.3f per second\n", N/tdiff);

    printf("testing public key scalar addition performance: ");
    gettimeofday(&start, NULL);
    for (i = 0; i < N; ++i) {
        ed25519_add_scalar(public_key, NULL, scalar);
    }
    gettimeofday(&end, NULL);
    tdiff = end.tv_sec - start.tv_sec + (end.tv_usec - start.tv_usec) / 1000000.0;
    printf("ed25519_add_scalar: %.3f per second\n", N/tdiff);

    printf("testing key exchange performance: ");
    gettimeofday(&start, NULL);
    for (i = 0; i < N; ++i) {
        ed25519_key_exchange(shared_secret, other_public_key, private_key);
    }
    gettimeofday(&end, NULL);
    tdiff = end.tv_sec - start.tv_sec + (end.tv_usec - start.tv_usec) / 1000000.0;
    printf("ed25519_key_exchange: %.3f per second\n", N/tdiff);
    
    return 0;
}
