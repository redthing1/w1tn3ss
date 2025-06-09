# injection debugging notes

## asan/ubsan interference with injection

**problem**: runtime injection fails with debug builds of w1tool

**cause**: addresssanitizer in injector process interferes with mach exception handling and thread manipulation

**evidence**:
- release w1tool → any target: works
- debug w1tool → any target: fails with "remote thread resume error"

**solution**: use release builds for injection testing

```sh
cmake -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release --parallel
./build-release/w1tool inject -L ./build-release/tests/libraries/tracer_lib.dylib -p <pid>
```

## ubsan alignment warnings

**problem**: ubsan reports misaligned access in mach exception data structures

**cause**: mig-generated structures use 4-byte packing but contain 8-byte integers

**solution**: targeted sanitizer suppression in exc_handler.c using `__attribute__((no_sanitize("alignment")))`

this is a known limitation when using ubsan with low-level system apis - the kernel may pass data that doesn't meet ubsan's strict alignment requirements.

## injection library dependencies

**critical**: injection libraries must not depend on sanitizer runtimes

target processes may not have asan initialized, causing injection failure.

**solution**: disable sanitizers for injection libraries in cmake:

```cmake
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT WIN32)
    target_compile_options(tracer_lib PRIVATE -fno-sanitize=all)
    target_link_options(tracer_lib PRIVATE -fno-sanitize=all)
endif()
```