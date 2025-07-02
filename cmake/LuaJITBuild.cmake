# luajitbuild.cmake - builds luajit from source using luajit-cmake wrapper
# provides cross-platform luajit static library build

# configuration options
option(WITNESS_LUAJIT_DISABLE_FFI "disable luajit ffi support" OFF)
option(WITNESS_LUAJIT_DISABLE_JIT "disable jit compilation (interpreter only)" OFF)
option(WITNESS_LUAJIT_ENABLE_LUA52COMPAT "enable lua 5.2 compatibility features" OFF)

# main function to build luajit static library
function(build_luajit_from_source)
    if(NOT EXISTS "${CMAKE_SOURCE_DIR}/src/third_party/luajit_cmake/CMakeLists.txt")
        message(FATAL_ERROR "luajit-cmake submodule not found. run: git submodule update --init --recursive")
    endif()
    
    if(NOT EXISTS "${CMAKE_SOURCE_DIR}/src/third_party/luajit/src/lua.h")
        message(FATAL_ERROR "luajit submodule not found. run: git submodule update --init --recursive")
    endif()
    
    # set luajit source directory for luajit-cmake wrapper
    set(LUAJIT_DIR "${CMAKE_SOURCE_DIR}/src/third_party/luajit" CACHE PATH "path to luajit source")
    
    # configure luajit build options
    set(LUAJIT_DISABLE_FFI ${WITNESS_LUAJIT_DISABLE_FFI} CACHE BOOL "disable luajit ffi")
    set(LUAJIT_DISABLE_JIT ${WITNESS_LUAJIT_DISABLE_JIT} CACHE BOOL "disable jit compilation")
    set(LUAJIT_ENABLE_LUA52COMPAT ${WITNESS_LUAJIT_ENABLE_LUA52COMPAT} CACHE BOOL "enable lua 5.2 compatibility")
    set(LUAJIT_BUILD_EXE OFF CACHE BOOL "disable luajit executable build")
    set(LUAJIT_BUILD_ALAMG OFF CACHE BOOL "disable amalgamated build")
    
    # set architecture manually to avoid try_compile issues in cross-compilation
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        set(LJ_DETECTED_ARCH "AArch64" CACHE STRING "luajit target architecture")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
        set(LJ_DETECTED_ARCH "x86_64" CACHE STRING "luajit target architecture")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i[3-6]86|x86")
        set(LJ_DETECTED_ARCH "x86" CACHE STRING "luajit target architecture")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
        set(LJ_DETECTED_ARCH "ARM" CACHE STRING "luajit target architecture")
    endif()
    
    # add luajit-cmake subdirectory
    add_subdirectory(${CMAKE_SOURCE_DIR}/src/third_party/luajit_cmake ${CMAKE_BINARY_DIR}/luajit_cmake)
    
    # ensure generated headers are available (luajit.h, etc.)
    if(TARGET luajit-header)
        target_include_directories(luajit-header INTERFACE ${CMAKE_BINARY_DIR}/luajit_cmake)
    endif()
    
    # export targets and variables for parent scope
    set(LUAJIT_STATIC_TARGET luajit::lib PARENT_SCOPE)
    set(LUAJIT_INCLUDE_DIRS ${LUA_INCLUDE_DIR} PARENT_SCOPE)
    set(LUAJIT_LIBRARIES luajit::lib PARENT_SCOPE)
    
    message(STATUS "configured luajit static library build using luajit-cmake")
endfunction()