# Standalone samples

This directory contains self-contained sample projects that build against the p1ll core without the full w1tn3ss build.

## p1ll_standalone

Build and run the standalone C++ and C API tests:

    cmake -G Ninja -S samples/standalone/p1ll_standalone -B build-p1ll-standalone
    cmake --build build-p1ll-standalone
    ./build-p1ll-standalone/test_p1ll_standalone
    ./build-p1ll-standalone/test_p1ll_capi

## p1ll_python

After building the Python bindings (see `doc/p1ll_python.md`), run:

    PYTHONPATH=build-p1ll-python python3 samples/standalone/p1ll_python/test_p1ll_python.py
