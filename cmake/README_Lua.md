# WITNESS Lua/Sol2 Integration

This directory contains a clean, cross-platform Lua/sol2 integration for WITNESS projects.

## Overview

- **LuaJIT**: Built from source using `luajit-cmake` wrapper for cross-platform compatibility
- **sol2**: Header-only C++ library for elegant Lua bindings
- **Static linking**: No runtime dependencies
- **Optional**: Easily enabled/disabled with `WITNESS_SCRIPT` option

## Files

- `LuaConfig.cmake` - Main configuration module with easy-to-use functions
- `LuaJITBuild.cmake` - LuaJIT build system using luajit-cmake wrapper

## Usage

### For new projects:

```cmake
include(${CMAKE_SOURCE_DIR}/cmake/LuaConfig.cmake)

# Setup the Lua environment (only if WITNESS_SCRIPT=ON)
setup_lua_environment()

# Configure your target with Lua dependencies
configure_target_with_lua(my_target)
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