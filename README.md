# w1tn3ss

cross-platform dynamic binary analysis tool powered by qbdi.

## build

for development:
```sh
cmake -B build-debug
cmake --build build-debug --parallel
```

for production use:
```sh
cmake -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release --parallel
```

on windows, to build 32-bit:
```sh
cmake -B build-win32 -DWITNESS_ARCH=x86 -DCMAKE_GENERATOR_PLATFORM=Win32 -DCMAKE_BUILD_TYPE=Release
```

## usage

### macos

inject w1tn3ss library into target process:
```sh
./build-macos/src/w1tool/w1tool inject -L ./build-macos/src/w1tn3ss/libw1tn3ss.dylib -n target_process
```

### general

inspect binary file:
```sh
./build-macos/src/w1tool/w1tool inspect -b /path/to/binary
```

## notes

runtime injection requires release build of w1tool on macos - debug builds with asan interfere with mach exception handling.