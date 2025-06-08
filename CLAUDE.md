# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build System

This project uses CMake with a flat build output structure:

```sh
cmake -B build-macos
cmake --build build-macos --parallel
```

Built artifacts appear directly in `build-macos/`:
- `w1tool` - command-line tool executable  
- `w1tn3ss.dylib` - analysis library (no lib prefix, no version suffix)

Debug builds are the default with ASan/UBSan enabled automatically on non-Windows platforms.

## Architecture

**w1tn3ss** is a cross-platform dynamic binary analysis tool built on QBDI (QuarkslaB Dynamic Binary Instrumentation).

### Core Components

- **src/w1tn3ss/** - Main analysis library
  - Uses `w1::` namespace with `w1::util` for logging
  - Configured as shared library by default (WITNESS_SHARED=ON)
  - Integrates with QBDI for binary instrumentation

- **src/w1tool/** - Command-line interface
  - Subcommand-based using args library (`ext/args.hpp`)
  - `inject` - inject w1tn3ss library into target process
  - `inspect` - analyze binary files
  - Shows help by default when run without arguments

- **src/common/** - Header-only library
  - Contains external dependencies like args.hpp
  - Interface-only CMake target for shared headers

### QBDI Integration

QBDI platform and architecture are auto-detected at CMake configure time:
- Platform: linux/osx/windows  
- Architecture: X86/X86_64/AARCH64/ARM
- Configuration: static library build, tests disabled, frida support enabled

## Code Style

- **snake_case** for all identifiers
- **lowercase comments** throughout
- **OTBS (One True Brace Style)** formatting
- Namespace: `w1::` for main code, `w1::util::` for utilities

## Testing Commands

```sh
# test w1tool help
./build-macos/w1tool

# test inject command
./build-macos/w1tool inject -L ./build-macos/w1tn3ss.dylib -n target_process

# test inspect command  
./build-macos/w1tool inspect -b /bin/ls
```

## Development Notes

- CMake output directories are configured to place binaries flat in build directory
- Library naming removes standard lib prefix and version suffixes
- QBDI tests are disabled to speed up builds
- All lowercase comments and snake_case conventions are enforced