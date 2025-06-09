# w1tn3ss

cross-platform dynamic binary analysis tool powered by qbdi.

## build

```sh
cmake -B build-macos
cmake --build build-macos --parallel
```

for production use:
```sh
cmake -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release --parallel
```

## usage

inject w1tn3ss library into target process:
```sh
./build-macos/src/w1tool/w1tool inject -L ./build-macos/src/w1tn3ss/libw1tn3ss.dylib -n target_process
```

inspect binary file:
```sh
./build-macos/src/w1tool/w1tool inspect -b /path/to/binary
```

## features

+ cross-platform dynamic binary instrumentation
+ qbdi-powered analysis engine  
+ command-line injection and inspection tools
+ shared/static library builds
+ debug builds with asan/ubsan by default

## notes

runtime injection requires release build of w1tool on macos - debug builds with asan interfere with mach exception handling.