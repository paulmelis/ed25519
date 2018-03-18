#ifdef WITH_PYTHON
#include <Python.h>
#include "pyapi.h"
#endif
#include <stdlib.h>
#include "hash.h"
#include "sha512.h"

void*
hash_create_context(void)
{
#ifdef WITH_PYTHON
    if (use_python_hash)
    {
        PyObject *res = PyObject_CallObject(py_hash_create_context, NULL);
        
        if (res == NULL)
        {
            print_python_error();
            // XXX and do what here?
            return NULL;
        }
        
        return res;
    }
#endif
    return malloc(sizeof(sha512_context));
}

void 
hash_free_context(void *context)
{
#ifdef WITH_PYTHON
    // XXX check for pyobject?
    if (use_python_hash)
        Py_DECREF((PyObject*)context);
    else
#endif
        free(context);
}

int 
hash_init(void *context)
{
#ifdef WITH_PYTHON
    if (use_python_hash)
    {
        PyObject *args = Py_BuildValue("(O)", (PyObject*)context);

        PyObject *res = PyObject_CallObject(py_hash_init, args);
        
        Py_DECREF(args);
        
        // XXX check return value
        
        if (res == NULL)
        {
            print_python_error();
            return 1;
        }
        
        return 0;
    }
    else
#endif
        return sha512_init(context);
}

int 
hash_update(void *context, const unsigned char *in, size_t inlen)
{
#ifdef WITH_PYTHON
    if (use_python_hash)
    {
        PyObject *args = Py_BuildValue("(Oy#)", (PyObject*)context, in, inlen);

        PyObject *res = PyObject_CallObject(py_hash_update, args);
        
        Py_DECREF(args);
        
        // XXX check return value
        
        if (res == NULL)
        {
            print_python_error();
            return 1;
        }
        
        return 0;
    }
    else
#endif
        return sha512_update(context, in, inlen);
}

int 
hash_final(void *context, unsigned char *out)
{
#ifdef WITH_PYTHON
    if (use_python_hash)
    {        
        PyObject *args = Py_BuildValue("(O)", (PyObject*)context);

        PyObject *res = PyObject_CallObject(py_hash_final, args);
        
        Py_DECREF(args);
        
        if (res == NULL)
        {
            print_python_error();
            return 1;
        }
        
        if (!PyBytes_Check(res) || PyBytes_Size(res) != 64)
        {
            fprintf(stderr, "Return value of hash_final() should be a bytes object of length 64");
            return 1;
        }
        
        memcpy(out, PyBytes_AsString(res), 64);
        
        return 0;
    }
    else
#endif
        return sha512_final(context, out);
}

int 
hash(const unsigned char *message, size_t message_len, unsigned char *out)
{
#ifdef WITH_PYTHON
    if (use_python_hash)
    {
        PyObject *args = Py_BuildValue("(y#)", message, message_len);
        if (args == NULL)
        {
            print_python_error();
            return 1;
        }

        PyObject *res = PyObject_CallObject(py_hash, args);
        
        Py_DECREF(args);
        
        if (res == NULL)
        {
            print_python_error();
            return 1;
        }
        
        if (!PyBytes_Check(res) || PyBytes_Size(res) != 64)
        {
            fprintf(stderr, "Return value of hash() should be a bytes object of length 64");
            return 1;
        }
        
        memcpy(out, PyBytes_AsString(res), 64);
        
        return 0;
    }
    else
#endif
        return sha512(message, message_len, out);
}
