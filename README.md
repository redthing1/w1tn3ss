# w1tn3ss

a cross-platform dynamic binary analysis platform powered by [qbdi](https://github.com/QBDI/QBDI).

## features

+ a framework for writing dynamic tracers
+ built-in tracers: coverage, memory, instruction, etc.
+ cross-platform library injection library
+ a tool for easy tracer injection

## build

build for any platform:
```sh
cmake -G Ninja -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release --parallel
```

to use a specific arch, configure `WITNESS_ARCH` (`x64`, `x86`, `arm64`)

## cli examples

collect coverage in drcov format using `w1cov`:
```sh
./build-release/w1tool cover -s ./build-release/tests/programs/runtime_injection_target
```

collect address trace using `w1trace`:
```sh
./build-release/w1tool tracer -n w1trace -s ./build-release/tests/programs/runtime_injection_target
```
