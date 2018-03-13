#include <Python.h>
#include "ed25519.h"

/*
There are no defined types for seeds, private keys, public keys, shared secrets or signatures. Instead simple unsigned char buffers are used with the following sizes:

unsigned char seed[32];
unsigned char signature[64];
unsigned char public_key[32];
unsigned char private_key[64];
unsigned char scalar[32];
unsigned char shared_secret[32];
*/

static char func_doc[] = "";

static PyObject*
py_create_keypair(PyObject* self, PyObject* args, PyObject *kwds)
{
    // void ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed)
    
    const char      *seed;
    int             seed_len;
    unsigned char   pubkey[32];
    unsigned char   privkey[64];
    
    if (!PyArg_ParseTuple(args, "y#", &seed, &seed_len))
        return NULL;
    
    if (seed_len != 32)
    {
        PyErr_SetString(PyExc_ValueError, "Seed must be 32 bytes long");
        return NULL;
    }
    
    ed25519_create_keypair(pubkey, privkey, (const unsigned char*)seed);
    
    return Py_BuildValue("y#y#", pubkey, 32, privkey, 64);
}

static PyObject*
py_get_pubkey(PyObject* self, PyObject* args, PyObject *kwds)
{
    // void ed25519_get_pubkey(unsigned char *public_key, const unsigned char *private_key)
    
    const char      *privkey;
    int             privkey_len;
    unsigned char   pubkey[32];
    
    if (!PyArg_ParseTuple(args, "y#", &privkey, &privkey_len))
        return NULL;
    
    if (privkey_len != 64)
    {
        PyErr_SetString(PyExc_ValueError, "Private key must be 64 bytes long");
        return NULL;
    }
    
    ed25519_get_pubkey((unsigned char *)pubkey, (const unsigned char *)privkey);
    
    return Py_BuildValue("y#", pubkey, 32);
}


static PyObject*
py_sign(PyObject* self, PyObject* args, PyObject *kwds)
{
    // void ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key)
    
    const char      *pubkey, *privkey, *message;
    int             pubkey_len, privkey_len, message_len;
    unsigned char   signature[64];
    
    if (!PyArg_ParseTuple(args, "y#y#y#", &message, &message_len, &pubkey, &pubkey_len, &privkey, &privkey_len))
        return NULL;
    
    if (pubkey_len != 32)
    {
        PyErr_SetString(PyExc_ValueError, "Public key must be 32 bytes long");
        return NULL;
    }
    
    if (privkey_len != 64)
    {
        PyErr_SetString(PyExc_ValueError, "Private key must be 64 bytes long");
        return NULL;
    }
    
    ed25519_sign(signature, (const unsigned char *)message, message_len, (const unsigned char *)pubkey, (const unsigned char *)privkey);
    
    return Py_BuildValue("y#", signature, 64);
}

static PyObject*
py_verify(PyObject* self, PyObject* args, PyObject *kwds)
{
    // int ed25519_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key)
    
    const char  *signature, *message, *pubkey;
    int         signature_len, message_len, pubkey_len;
    int         res;
    
    if (!PyArg_ParseTuple(args, "y#y#y#", &signature, &signature_len, &message, &message_len, &pubkey, &pubkey_len))
        return NULL;

    if (signature_len != 64)
    {
        PyErr_SetString(PyExc_ValueError, "Signature must be 64 bytes long");
        return NULL;
    }
    
    if (pubkey_len != 32)
    {
        PyErr_SetString(PyExc_ValueError, "Public key must be 32 bytes long");
        return NULL;
    }
    
    res = ed25519_verify((const unsigned char *)signature, (const unsigned char *)message, message_len, (const unsigned char *)pubkey);
    
    return PyBool_FromLong(res);
}

static PyMethodDef ModuleMethods[] =
{    
    // {"readply", (PyCFunction)readply, METH_VARARGS|METH_KEYWORDS, readply_func_doc},
    {"create_keypair",  (PyCFunction)py_create_keypair, METH_VARARGS|METH_KEYWORDS, func_doc},
    {"get_pubkey",      (PyCFunction)py_get_pubkey,     METH_VARARGS|METH_KEYWORDS, func_doc},
    {"sign",            (PyCFunction)py_sign,           METH_VARARGS|METH_KEYWORDS, func_doc},
    {"verify",          (PyCFunction)py_verify,         METH_VARARGS|METH_KEYWORDS, func_doc},
    //add_scalar
    //key_exchange
    //create_seed
     {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module =
{
   PyModuleDef_HEAD_INIT,
   "ed25519",               /* name of module */
   NULL,                    /* module documentation, may be NULL */
   -1,                      /* size of per-interpreter state of the module,
                            or -1 if the module keeps state in global variables. */
   ModuleMethods
};

PyMODINIT_FUNC
PyInit_ed25519(void)
{
    PyObject *m;

    m = PyModule_Create(&module);
    if (m == NULL)
        return NULL;

    //PyModule_AddObject(m, "error", SpamError);
    return m;
}
