from setuptools import setup, Extension

module1 = Extension('ed25519', 
    include_dirs = ['./src'],
    #define_macros=[('ED25519_NO_SEED', '1')],
    sources = ['src/pyapi.c', 'src/add_scalar.c', 'src/fe.c', 'src/ge.c', 'src/hash.c', 'src/key_exchange.c', 'src/keypair.c', 'src/sc.c', 'src/seed.c', 'src/sha512.c', 'src/sign.c', 'src/verify.c'],
    language='c')

setup(
    name = 'ed25519',
    author = 'Paul Melis',    
    author_email = 'paul.melis@gmail.com',
    version = '1.0',
    description = '',
    ext_modules = [module1]
)
