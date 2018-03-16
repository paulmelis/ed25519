#ifndef HASH_H
#define HASH_H

#include <stddef.h>

// All routines should return 0 on success, 1 on failure

// Create context to pass to hash functions
void *hash_create_context(void);

// Free the context
void hash_free_context(void *context);

// Initialize the given context
int hash_init(void *context);

// Update the hash with the given message input
int hash_update(void *context, const unsigned char *in, size_t inlen);

// Return the final 64-byte hash in out
int hash_final(void *context, unsigned char *out);

// Compute the hash for the given message
int hash(const unsigned char *message, size_t message_len, unsigned char *out);

extern int use_python_hash;

#endif