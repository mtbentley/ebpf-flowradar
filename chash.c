#include <Python.h>
#include "xdp-flowradar_kern.c"
#include <stdint.h>

static PyObject* c_hash(PyObject *self, PyObject *args) {
    uint16_t result;
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    uint8_t proto;
    uint16_t host;
    uint8_t k;

    if (!(PyArg_ParseTuple(
        args, "IIHHBHB", &saddr, &daddr, &sport, &dport, &proto, &host, &k
    ))) {
        return NULL;
    }

    struct five_tuple ft = {
        .sport = sport,
        .dport = dport,
        .saddr = saddr,
        .daddr = daddr,
        .proto = proto,
    };

    return Py_BuildValue("H", hash(host, k, &ft));
}

static PyMethodDef CHashMethods[] = 
{
    {"c_hash", c_hash, METH_VARARGS, "c hash"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef cHashMod =
{
    PyModuleDef_HEAD_INIT,
    "cHash", "c hash",
    -1,
    CHashMethods
};

PyMODINIT_FUNC
PyInit_cHash(void) {
    return PyModule_Create(&cHashMod);
}
