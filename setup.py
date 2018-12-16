from distutils.core import setup, Extension

cHash_module = Extension('cHash', sources=['chash.c'])

setup(ext_modules=[cHash_module])
