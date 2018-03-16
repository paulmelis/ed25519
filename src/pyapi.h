#ifndef PYAPI_H
#define PYAPI_H

extern int use_python_hash;

extern PyObject* py_hash_create_context;
extern PyObject* py_hash_free_context;
extern PyObject* py_hash_init;
extern PyObject* py_hash_update;
extern PyObject* py_hash_final;
extern PyObject* py_hash;

void print_python_error(void);

#endif

