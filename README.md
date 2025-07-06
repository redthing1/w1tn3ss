# w1tn3ss

a cross-platform dynamic binary analysis platform powered by [qbdi](https://github.com/QBDI/QBDI) and [lief](https://github.com/lief-project/LIEF).

## features

+ a framework for writing dynamic tracers
+ built-in tracers: coverage, memory, instruction, etc.
+ real-time shared library call tracing via abi analysis
+ scriptable tracers with [luajit](https://luajit.org/)
+ cross-platform library injection library
+ a tool for easy tracer injection

## build

build for any platform (with script and lief enabled):
```sh
cmake -G Ninja -B build-release -DCMAKE_BUILD_TYPE=Release -DWITNESS_SCRIPT=ON -DWITNESS_LIEF=ON
cmake --build build-release --parallel
```

to use a specific arch, configure `WITNESS_ARCH` (`x64`, `x86`, `arm64`)

## cli examples

### coverage & tracing

collect coverage in drcov format using `w1cov`:
```sh
./build-release/w1tool cover -s ./build-release/tests/programs/runtime_injection_target
```

collect address trace using `w1trace`:
```sh
./build-release/w1tool tracer -n w1trace -s ./build-release/tests/programs/runtime_injection_target
```

### real-time api call analysis

on macos, dump your dyld cache:
```sh
brew install keith/formulae/dyld-shared-cache-extractor
dyld-shared-cache-extractor /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e /tmp/libraries
```

trace api calls in real time using:
```sh
DYLD_SHARED_CACHE_DUMP_DIR=/tmp/libraries ./build-release/w1tool tracer -n w1xfer --debug 1 -c analyze_apis=true -s ./build-release/tests/programs/runtime_injection_target
```
