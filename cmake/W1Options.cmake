# shared options and target defaults for w1tn3ss
include_guard()

set(W1_SOURCE_DIR "${PROJECT_SOURCE_DIR}")
set(W1_CMAKE_DIR "${PROJECT_SOURCE_DIR}/cmake")

set(W1_IS_TOP_LEVEL FALSE)
if(PROJECT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(W1_IS_TOP_LEVEL TRUE)
endif()

function(w1_set_cache_default VAR TYPE VALUE DOC)
    if(NOT DEFINED ${VAR})
        set(${VAR} "${VALUE}" CACHE ${TYPE} "${DOC}")
    endif()
endfunction()

option(W1_USE_SYSTEM_DEPS "Prefer system dependencies via find_package" OFF)
option(W1_BUILD_ALL "Build all w1tn3ss components" ${W1_IS_TOP_LEVEL})

option(WITNESS_BUILD_STATIC "Build static libraries" ON)
option(WITNESS_BUILD_SHARED "Build shared libraries" ON)
option(WITNESS_QBDI_EXTRAS "Build QBDI examples/tests/tools" OFF)

option(WITNESS_LIEF "Enable LIEF support" ON)
option(WITNESS_ASMR "Build w1asmr disassembler/assembler" OFF)
option(WITNESS_SCRIPT "Enable scripting support" OFF)
set(WITNESS_SCRIPT_ENGINE "lua" CACHE STRING "Script engine to use (lua or js)")
set_property(CACHE WITNESS_SCRIPT_ENGINE PROPERTY STRINGS "lua" "js")

option(WITNESS_LUAJIT_DISABLE_FFI "Disable luajit ffi support" OFF)
option(WITNESS_LUAJIT_DISABLE_JIT "Disable jit compilation" OFF)
option(WITNESS_LUAJIT_ENABLE_LUA52COMPAT "Enable lua 5.2 compatibility features" OFF)

if(W1_IS_TOP_LEVEL)
    w1_set_cache_default(W1_ENABLE_DEV_TOOLS BOOL ON "Enable formatting and tidy helpers")
    w1_set_cache_default(W1_EXPORT_COMPILE_COMMANDS BOOL ON "Generate compile_commands.json")
else()
    w1_set_cache_default(W1_ENABLE_DEV_TOOLS BOOL OFF "Enable formatting and tidy helpers")
    w1_set_cache_default(W1_EXPORT_COMPILE_COMMANDS BOOL OFF "Generate compile_commands.json")
endif()

if(W1_ENABLE_DEV_TOOLS)
    w1_set_cache_default(W1_ENABLE_CLANG_TIDY BOOL ON "Enable clang-tidy for w1 targets")
else()
    w1_set_cache_default(W1_ENABLE_CLANG_TIDY BOOL OFF "Enable clang-tidy for w1 targets")
endif()

if(NOT DEFINED W1_CLANG_TIDY_EXCLUDE_DIRS)
    set(_w1_default_tidy_excludes "${W1_SOURCE_DIR}/src/third_party")
    if(EXISTS "${_w1_default_tidy_excludes}")
        set(W1_CLANG_TIDY_EXCLUDE_DIRS "${_w1_default_tidy_excludes}" CACHE STRING "Directories excluded from clang-tidy")
    else()
        set(W1_CLANG_TIDY_EXCLUDE_DIRS "" CACHE STRING "Directories excluded from clang-tidy")
    endif()
endif()

if(W1_EXPORT_COMPILE_COMMANDS)
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
endif()

add_library(w1_config INTERFACE)
add_library(w1::config ALIAS w1_config)

target_compile_features(w1_config INTERFACE cxx_std_20)

if(WIN32)
    target_compile_definitions(w1_config INTERFACE
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        _CRT_SECURE_NO_WARNINGS
    )
    target_link_libraries(w1_config INTERFACE psapi kernel32 user32)
elseif(UNIX AND NOT APPLE)
    target_link_libraries(w1_config INTERFACE dl)
endif()

add_library(w1_warnings INTERFACE)
add_library(w1::warnings ALIAS w1_warnings)

target_compile_options(w1_warnings INTERFACE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra>
    $<$<CXX_COMPILER_ID:MSVC>:/EHsc>
)

function(w1_apply_clang_tidy TARGET_NAME)
    if(NOT W1_ENABLE_CLANG_TIDY)
        return()
    endif()

    if(NOT W1_CLANG_TIDY_COMMAND)
        return()
    endif()

    get_target_property(_w1_aliased ${TARGET_NAME} ALIASED_TARGET)
    if(_w1_aliased)
        return()
    endif()

    get_target_property(_w1_imported ${TARGET_NAME} IMPORTED)
    if(_w1_imported)
        return()
    endif()

    get_target_property(_w1_target_type ${TARGET_NAME} TYPE)
    if(_w1_target_type STREQUAL "INTERFACE_LIBRARY" OR _w1_target_type STREQUAL "UTILITY")
        return()
    endif()

    get_target_property(_w1_skip_tidy ${TARGET_NAME} W1_CLANG_TIDY_SKIP)
    if(_w1_skip_tidy)
        return()
    endif()

    get_target_property(_w1_target_source_dir ${TARGET_NAME} SOURCE_DIR)
    if(_w1_target_source_dir AND W1_CLANG_TIDY_EXCLUDE_DIRS)
        file(TO_CMAKE_PATH "${_w1_target_source_dir}" _w1_target_source_dir_norm)
        foreach(_w1_exclude_dir IN LISTS W1_CLANG_TIDY_EXCLUDE_DIRS)
            if(NOT _w1_exclude_dir)
                continue()
            endif()
            file(TO_CMAKE_PATH "${_w1_exclude_dir}" _w1_exclude_dir_norm)
            set(_w1_exclude_dir_norm "${_w1_exclude_dir_norm}/")
            set(_w1_target_source_dir_check "${_w1_target_source_dir_norm}/")
            string(FIND "${_w1_target_source_dir_check}" "${_w1_exclude_dir_norm}" _w1_exclude_idx)
            if(_w1_exclude_idx EQUAL 0)
                return()
            endif()
        endforeach()
    endif()

    set_target_properties(${TARGET_NAME} PROPERTIES
        C_CLANG_TIDY "${W1_CLANG_TIDY_COMMAND}"
        CXX_CLANG_TIDY "${W1_CLANG_TIDY_COMMAND}"
    )
endfunction()

function(w1_target_defaults TARGET_NAME)
    target_link_libraries(${TARGET_NAME} PUBLIC w1::config)
    target_link_libraries(${TARGET_NAME} PRIVATE w1::warnings)
    w1_apply_clang_tidy(${TARGET_NAME})
endfunction()
