# CLAUDE.md

## Build

```sh
cmake -B build-macos
cmake --build build-macos --parallel
```

Debug builds default with ASan/UBSan. For runtime injection on macOS:
```sh
cmake -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release --parallel
```

## Architecture

- **src/w1tn3ss/** - analysis library using QBDI
- **src/w1tool/** - CLI with `inject` and `inspect` commands  
- **src/w1nj3ct/** - injection library
- **src/common/** - shared headers

## Code Style

- snake_case, lowercase comments, OTBS formatting
- namespace: `w1::`, logging: redlog

## Testing

```sh
# basic usage
./build-macos/w1tool
./build-macos/w1tool inspect -b /bin/ls

# injection with test programs
./build-macos/w1tool inject -L ./build-macos/tests/libraries/tracer_lib.dylib -b ./build-macos/tests/programs/simple_target

# verbosity: -v (info), -vv (verbose), -vvv (trace), -vvvv (debug)
./build-macos/w1tool -vv inject -L ./build-macos/tests/libraries/memory_lib.dylib -b ./build-macos/tests/programs/multi_threaded_target
```

## Notes

- runtime injection requires release build of w1tool on macos (asan interference)
- component loggers: `w1tool`, `w1tool.inject`, `w1tool.inspect`, `w1tn3ss`, `w1nj3ct`
- structured logging: `redlog::field("key", value)`