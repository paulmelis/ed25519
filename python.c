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

static char create_keypair_doc[] = 
"create_keypair(seed) -> (public_key, private_key)\n\
\n\
Creates a new key pair from the given seed\n\
";

static char get_pubkey_doc[] = 
"get_pubkey(private_key) -> public_key\n\
\n\
Derives the public key for the given private key, which\n\
must be a bytes object of length 64 holding a valid\n\
private key.\n\
";
   
static char sign_doc[] =    
"sign(message, public_key, private_key) -> signature\n\
\n\
Creates a signature for a message using the given key pair.\n\
";

static char verify_doc[] =    
"verify(signature, message, public_key) -> bool\n\
\n\
Verifies the signature on a message using the given public key.\n\
\n\
Returns True if the signature matches, False otherwise.\n\
";
  
static char privkey_from_ref10_doc[] =    
"privkey_from_ref10(ref10_private_key) -> private_key\n\
\n\
SUPERCOP's ref10 implementation stores the private key\n\
as the 64-byte concatenation of the seed and public key (32 + 32).\n\
This library stores a private key as the hash of the seed.\n\
Derive such a private key from a ref10 private key.\n\
";


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
py_privkey_from_ref10(PyObject* self, PyObject* args, PyObject *kwds)
{
    // void ed25519_privkey_from_ref10(unsigned char *private_key, const unsigned char *ref10_private_key)
    
    const char      *ref10_privkey;
    int             ref10_privkey_len;
    unsigned char   privkey[64];
    
    if (!PyArg_ParseTuple(args, "y#", &ref10_privkey, &ref10_privkey_len))
        return NULL;
    
    if (ref10_privkey_len != 64)
    {
        PyErr_SetString(PyExc_ValueError, "Ref10 private key must be 64 bytes long");
        return NULL;
    }
    
    ed25519_privkey_from_ref10((unsigned char *)privkey, (const unsigned char *)ref10_privkey);
    
    return Py_BuildValue("y#", privkey, 64);
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
    {"create_keypair",  (PyCFunction)py_create_keypair, METH_VARARGS|METH_KEYWORDS, create_keypair_doc},
    {"get_pubkey",      (PyCFunction)py_get_pubkey,     METH_VARARGS|METH_KEYWORDS, get_pubkey_doc},
    {"privkey_from_ref10", (PyCFunction)py_privkey_from_ref10,     METH_VARARGS|METH_KEYWORDS, privkey_from_ref10_doc},
    {"sign",            (PyCFunction)py_sign,           METH_VARARGS|METH_KEYWORDS, sign_doc},
    {"verify",          (PyCFunction)py_verify,         METH_VARARGS|METH_KEYWORDS, verify_doc},
    //add_scalar
    //key_exchange
    //create_seed
     {NULL, NULL, 0, NULL}
};

PyDoc_STRVAR(module_doc, 
"High-speed high-security signatures\n\
\n\
Module providing Ed25519 message signatures, based on the\n\
implementation at https://github.com/orlp/ed25519.\n\
\n\
Keys and signatures are all stored in bytes() objects, with the\n\
following sizes in bytes:\n\
\n\
    seed          : 32\n\
    signature     : 64\n\
    public_key    : 32\n\
    private_key   : 64\n\
    scalar        : 32\n\
    shared_secret : 32\n\
\n\
Messages to sign should also be passed as bytes() objects.\n\
\n\
Note that this library stores the private key as the hash of\n\
the seed and not as a concatenation of the seed and the public key\n\
(as some other Ed25519 implementations do). See privkey_from_ref10()\n\
for more information.\n\
");

static struct PyModuleDef module =
{
   PyModuleDef_HEAD_INIT,
   "ed25519",               /* name of module */
   module_doc,              /* module documentation, may be NULL */
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
