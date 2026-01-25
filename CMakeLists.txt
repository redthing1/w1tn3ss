cmake_minimum_required(VERSION 3.16)

project(w1tn3ss
    VERSION 0.1.0
    DESCRIPTION "Cross-platform dynamic binary analysis tool"
    LANGUAGES C CXX ASM
)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    message(FATAL_ERROR "GCC is not supported. Configure with Clang instead.")
endif()

include(cmake/W1Init.cmake)
include(cmake/WindowsSymbolConfig.cmake)

function(w1_component_option_name NAME OUT_VAR)
    string(TOUPPER "${NAME}" _upper)
    string(REPLACE "-" "_" _upper "${_upper}")
    set(${OUT_VAR} "W1_BUILD_${_upper}" PARENT_SCOPE)
endfunction()

set(W1_COMPONENTS
    w1base
    w1h00k
    w1monitor
    w1formats
    w1runtime
    w1instrument
    w1analysis
    w1import
    w1dump
    w1gadget
    w1rewind
    tracers
    w1asmr
    p1ll
    p1llx
    w1nj3ct
    w1debugger
    w1tool
    w1replay
    p01s0n
)

set(W1_COMPONENT_DIR_w1base "src/w1base")
set(W1_COMPONENT_DIR_w1h00k "src/w1h00k")
set(W1_COMPONENT_DIR_w1monitor "src/w1monitor")
set(W1_COMPONENT_DIR_w1formats "src/w1formats")
set(W1_COMPONENT_DIR_w1runtime "src/w1runtime")
set(W1_COMPONENT_DIR_w1instrument "src/w1instrument")
set(W1_COMPONENT_DIR_w1analysis "src/w1analysis")
set(W1_COMPONENT_DIR_w1import "src/w1import")
set(W1_COMPONENT_DIR_w1dump "src/w1dump")
set(W1_COMPONENT_DIR_w1gadget "src/w1gadget")
set(W1_COMPONENT_DIR_w1rewind "src/w1rewind")
set(W1_COMPONENT_DIR_tracers "src/tracers")
set(W1_COMPONENT_DIR_w1asmr "src/w1asmr")
set(W1_COMPONENT_DIR_p1ll "src/p1ll")
set(W1_COMPONENT_DIR_p1llx "src/p1llx")
set(W1_COMPONENT_DIR_w1nj3ct "src/w1nj3ct")
set(W1_COMPONENT_DIR_w1debugger "src/w1debugger")
set(W1_COMPONENT_DIR_w1tool "src/w1tool")
set(W1_COMPONENT_DIR_w1replay "src/w1replay")
set(W1_COMPONENT_DIR_p01s0n "src/p01s0n")

set(W1_COMPONENT_DEPS_w1base "")
set(W1_COMPONENT_DEPS_w1h00k "w1base;w1asmr")
set(W1_COMPONENT_DEPS_w1monitor "w1base;w1h00k")
set(W1_COMPONENT_DEPS_w1formats "")
set(W1_COMPONENT_DEPS_w1runtime "")
set(W1_COMPONENT_DEPS_w1instrument "w1runtime;w1base")
set(W1_COMPONENT_DEPS_w1analysis "w1runtime")
set(W1_COMPONENT_DEPS_w1import "")
set(W1_COMPONENT_DEPS_w1dump "w1formats;w1runtime")
set(W1_COMPONENT_DEPS_w1gadget "")
set(W1_COMPONENT_DEPS_w1rewind "w1base")
set(W1_COMPONENT_DEPS_tracers "w1instrument;w1formats;w1analysis;w1rewind;w1dump;w1gadget")
set(W1_COMPONENT_DEPS_w1asmr "w1base")
set(W1_COMPONENT_DEPS_p1ll "w1asmr")
set(W1_COMPONENT_DEPS_p1llx "p1ll;w1base;w1nj3ct")
set(W1_COMPONENT_DEPS_w1nj3ct "")
set(W1_COMPONENT_DEPS_w1debugger "")
set(W1_COMPONENT_DEPS_w1tool "w1base;w1dump;w1formats;w1import;w1nj3ct;w1debugger")
set(W1_COMPONENT_DEPS_w1replay "w1base;w1rewind")
set(W1_COMPONENT_DEPS_p01s0n "p1ll")

foreach(component IN LISTS W1_COMPONENTS)
    w1_component_option_name("${component}" _opt)
    w1_set_cache_default(${_opt} BOOL ${W1_BUILD_ALL} "Build component ${component}")
endforeach()

if(W1_BUILD_W1H00K AND NOT WITNESS_ASMR)
    message(STATUS "Enabling WITNESS_ASMR because w1h00k depends on w1asmr")
    set(WITNESS_ASMR ON CACHE BOOL "Build w1asmr disassembler/assembler" FORCE)
endif()

function(w1_enable_component NAME)
    get_property(_already_set GLOBAL PROPERTY "W1_COMPONENT_ENABLED_${NAME}")
    if(_already_set)
        return()
    endif()
    set_property(GLOBAL PROPERTY "W1_COMPONENT_ENABLED_${NAME}" TRUE)

    foreach(dep IN LISTS W1_COMPONENT_DEPS_${NAME})
        if(dep)
            w1_enable_component("${dep}")
        endif()
    endforeach()

    w1_component_option_name("${NAME}" _opt)
    if(DEFINED ${_opt} AND NOT ${_opt})
        message(STATUS "Enabling ${NAME} because it is required")
    endif()
    set(${_opt} ON CACHE BOOL "Build component ${NAME}" FORCE)

    set(_dir "${W1_COMPONENT_DIR_${NAME}}")
    if(NOT _dir)
        message(FATAL_ERROR "Unknown component directory for ${NAME}")
    endif()

    add_subdirectory("${_dir}")
endfunction()

foreach(component IN LISTS W1_COMPONENTS)
    w1_component_option_name("${component}" _opt)
    if(${_opt})
        w1_enable_component("${component}")
    endif()
endforeach()

if(W1_IS_TOP_LEVEL)
    w1_set_cache_default(BUILD_TESTS BOOL ${W1_BUILD_ALL} "Build test programs and libraries")
    w1_set_cache_default(BUILD_SAMPLES BOOL ${W1_BUILD_ALL} "Build sample programs")
else()
    w1_set_cache_default(BUILD_TESTS BOOL OFF "Build test programs and libraries")
    w1_set_cache_default(BUILD_SAMPLES BOOL OFF "Build sample programs")
endif()

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
    add_subdirectory(tests)
endif()

if(BUILD_SAMPLES)
    add_subdirectory(samples)
endif()

if(WIN32 AND MSVC)
    apply_windows_symbol_resolution_to_all()
endif()

if(W1_ENABLE_DEV_TOOLS)
    include(cmake/FormattingConfig.cmake)
    include(cmake/TidyConfig.cmake)
endif()

if(W1_IS_TOP_LEVEL AND W1_ENABLE_PACKAGING)
    include(cmake/W1Packaging.cmake)
endif()
