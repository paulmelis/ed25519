#include <stdlib.h>
#include "hash.h"
#include "sha512.h"

int use_python_hash=0;

void *
hash_create_context(void)
{
    if (use_python_hash)
        // XXX
        return NULL;
    
    return malloc(sizeof(sha512_context));
}

void 
hash_free_context(void *context)
{
    free(context);
}

int 
hash_init(void *context)
{
    if (use_python_hash)
    {
        // XXX
        return 0;
    }
    else
        return sha512_init(context);
}

int 
hash_update(void *context, const unsigned char *in, size_t inlen)
{
    if (use_python_hash)
    {
        // XXX
        return 0;
    }
    else
        return sha512_update(context, in, inlen);
}

int 
hash_final(void *context, unsigned char *out)
{
    if (use_python_hash)
    {
        // XXX
        return 0;
    }
    else
        return sha512_final(context, out);
}

int 
hash(const unsigned char *message, size_t message_len, unsigned char *out)
{
    if (use_python_hash)
    {
        // XXX
        return 0;
    }
    else
        return sha512(message, message_len, out);
}
