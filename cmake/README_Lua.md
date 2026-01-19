# WITNESS Lua/Sol2 Integration

This directory contains a clean, cross-platform Lua/sol2 integration for WITNESS projects.

## Overview

- **LuaJIT**: Built from source using `luajit-cmake` wrapper for cross-platform compatibility
- **sol2**: Header-only C++ library for elegant Lua bindings
- **Static linking**: No runtime dependencies
- **Optional**: Easily enabled/disabled with `WITNESS_SCRIPT` option

## Files

- `LuaJITBuild.cmake` - LuaJIT build system using luajit-cmake wrapper (used internally by w1tn3ss)

## Usage

### For new projects (inside w1tn3ss)

Enable scripting and link to the Lua interface target:

```cmake
set(WITNESS_SCRIPT ON CACHE BOOL "" FORCE)
add_subdirectory(path/to/w1tn3ss w1tn3ss_build)

target_link_libraries(my_target PRIVATE w1::lua)
```

### Configuration options:

```bash
# Enable Lua scripting support
cmake -DWITNESS_SCRIPT=ON ...

# Optional LuaJIT configuration
cmake -DWITNESS_SCRIPT=ON \
      -DWITNESS_LUAJIT_DISABLE_FFI=OFF \
      -DWITNESS_LUAJIT_DISABLE_JIT=OFF \
      -DWITNESS_LUAJIT_ENABLE_LUA52COMPAT=OFF \
      ...
```

## Dependencies

Required submodules (auto-checked):
- `src/third_party/luajit` - LuaJIT source code
- `src/third_party/luajit_cmake` - CMake wrapper for LuaJIT  
- `src/third_party/sol2` - sol2 header library

Initialize with: `git submodule update --init --recursive`

## Example Usage in Code

```cpp
#ifdef WITNESS_SCRIPT_ENABLED
#include <sol/sol.hpp>

void init_lua() {
    sol::state lua;
    lua.open_libraries(sol::lib::base, sol::lib::package);
    lua["hello"] = []() { return "Hello from Lua!"; };
}
#endif
```
