cmake_minimum_required(VERSION 3.12)

project(w1tn3ss
    VERSION 0.1.0
    DESCRIPTION "Cross-platform dynamic binary analysis tool"
    LANGUAGES C CXX ASM
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Default to Release build
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Disable SAFESEH globally for 32-bit Windows builds (QBDI assembly incompatible)
if(WIN32 AND CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /SAFESEH:NO")
    set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} /SAFESEH:NO")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SAFESEH:NO")
endif()

# # Sanitizers disabled by default (can cause issues)
# if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT WIN32)
#     set(SANITIZER_FLAGS "-fsanitize=address;-fsanitize=undefined")
# endif()

# options
option(WITNESS_BUILD_STATIC "Build static libraries" ON)
option(WITNESS_BUILD_SHARED "Build shared libraries" ON)
option(WITNESS_QBDI_EXTRAS "Build QBDI with examples, tests and additional tools" OFF)

# Auto-detect platform and architecture for QBDI
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(QBDI_PLATFORM "linux" CACHE STRING "QBDI Platform" FORCE)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(QBDI_PLATFORM "osx" CACHE STRING "QBDI Platform" FORCE)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(QBDI_PLATFORM "windows" CACHE STRING "QBDI Platform" FORCE)
else()
    message(FATAL_ERROR "Unsupported platform for QBDI: ${CMAKE_SYSTEM_NAME}")
endif()

# Architecture detection and configuration
if(NOT DEFINED WITNESS_ARCH OR WITNESS_ARCH STREQUAL "Auto")
    # Auto-detect architecture
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64")
        set(QBDI_ARCH "X86_64" CACHE STRING "QBDI Architecture")
        set(WITNESS_ARCH "x64" CACHE STRING "Witness Architecture")
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "i386" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "i686")
        set(QBDI_ARCH "X86" CACHE STRING "QBDI Architecture")
        set(WITNESS_ARCH "x86" CACHE STRING "Witness Architecture")
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
        set(QBDI_ARCH "AARCH64" CACHE STRING "QBDI Architecture")
        set(WITNESS_ARCH "arm64" CACHE STRING "Witness Architecture")
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm")
        set(QBDI_ARCH "ARM" CACHE STRING "QBDI Architecture")
        set(WITNESS_ARCH "arm" CACHE STRING "Witness Architecture")
    else()
        message(FATAL_ERROR "Unsupported architecture for auto-detection: ${CMAKE_SYSTEM_PROCESSOR}")
    endif()
    message(STATUS "Auto-detected architecture: ${WITNESS_ARCH}")
else()
    # User-specified architecture - validate and map to QBDI_ARCH
    if(WITNESS_ARCH STREQUAL "x64")
        set(QBDI_ARCH "X86_64" CACHE STRING "QBDI Architecture")
    elseif(WITNESS_ARCH STREQUAL "x86")
        set(QBDI_ARCH "X86" CACHE STRING "QBDI Architecture")
    elseif(WITNESS_ARCH STREQUAL "arm64")
        set(QBDI_ARCH "AARCH64" CACHE STRING "QBDI Architecture")
    else()
        message(FATAL_ERROR "Invalid WITNESS_ARCH: ${WITNESS_ARCH}. Must be one of: x64, x86, arm64, Auto")
    endif()
    message(STATUS "Using user-specified architecture: ${WITNESS_ARCH}")
endif()

message(STATUS "WITNESS Architecture: ${WITNESS_ARCH}")
message(STATUS "QBDI Platform: ${QBDI_PLATFORM}")
message(STATUS "QBDI Architecture: ${QBDI_ARCH}")

# Platform-specific architecture configuration
if(WIN32 AND WITNESS_ARCH STREQUAL "x86")
    # Force 32-bit build on Windows when targeting x86
    set(CMAKE_GENERATOR_PLATFORM "Win32" CACHE STRING "Platform for 32-bit builds" FORCE)
    # Ensure all targets are built for 32-bit
    set(CMAKE_SIZEOF_VOID_P 4)
    message(STATUS "Configured for Windows 32-bit build")
endif()

# Configure QBDI
set(QBDI_STATIC_LIBRARY ON)
set(QBDI_SHARED_LIBRARY ON)
set(QBDI_LOG_DEBUG OFF)
set(QBDI_TOOLS_QBDIPRELOAD ON)
set(QBDI_CCACHE ON)
set(QBDI_DISABLE_AVX OFF)
set(QBDI_ASAN OFF)

# QBDI optional features
if(WITNESS_QBDI_EXTRAS)
    set(QBDI_TOOLS_PYQBDI ON)
    set(QBDI_TOOLS_FRIDAQBDI ON)
    set(QBDI_TEST ON)
    set(QBDI_EXAMPLES ON)
    set(QBDI_BENCHMARK ON)
else()
    set(QBDI_TOOLS_PYQBDI OFF)
    set(QBDI_TOOLS_FRIDAQBDI OFF)
    set(QBDI_TEST OFF)
    set(QBDI_EXAMPLES ON)
    set(QBDI_BENCHMARK OFF)
endif()

# add third-party libraries
add_subdirectory(src/third_party/qbdi)

# configure redlog
set(REDLOG_BUILD_EXAMPLES OFF)
set(REDLOG_BUILD_TESTS OFF)
add_subdirectory(src/third_party/redlog_cpp)

# add project subdirectories
add_subdirectory(src/common)
add_subdirectory(src/w1tn3ss)
add_subdirectory(src/w1nj3ct)
add_subdirectory(src/w1tool)

# add tests (optional)
option(BUILD_TESTS "Build test programs and libraries" ON)
if(BUILD_TESTS)
    add_subdirectory(tests)
endif()

# add examples (optional)
option(BUILD_EXAMPLES "Build example programs" ON)
if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Code formatting with clang-format
find_program(CLANG_FORMAT_EXECUTABLE
    NAMES clang-format clang-format-18 clang-format-17 clang-format-16 clang-format-15
    DOC "Path to clang-format executable"
)

if(CLANG_FORMAT_EXECUTABLE)
    message(STATUS "clang-format found: ${CLANG_FORMAT_EXECUTABLE}")
    
    # Find all source files to format (excluding third-party and build directories)
    file(GLOB_RECURSE ALL_SOURCE_FILES
        "${CMAKE_SOURCE_DIR}/src/w1tn3ss/*.cpp"
        "${CMAKE_SOURCE_DIR}/src/w1tn3ss/*.hpp"
        "${CMAKE_SOURCE_DIR}/src/w1nj3ct/*.cpp"
        "${CMAKE_SOURCE_DIR}/src/w1nj3ct/*.hpp"
        "${CMAKE_SOURCE_DIR}/src/w1tool/*.cpp"
        "${CMAKE_SOURCE_DIR}/src/w1tool/*.hpp"
        "${CMAKE_SOURCE_DIR}/src/common/*.cpp"
        "${CMAKE_SOURCE_DIR}/src/common/*.hpp"
        "${CMAKE_SOURCE_DIR}/tests/*.cpp"
        "${CMAKE_SOURCE_DIR}/tests/*.hpp"
    )
    
    # Create format target
    add_custom_target(w1-format
        COMMAND ${CLANG_FORMAT_EXECUTABLE} -i -style=file ${ALL_SOURCE_FILES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Formatting w1tn3ss code with clang-format"
        VERBATIM
    )
    
    # Create format-check target
    add_custom_target(w1-format-check
        COMMAND ${CLANG_FORMAT_EXECUTABLE} --dry-run --Werror -style=file ${ALL_SOURCE_FILES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Checking w1tn3ss code formatting with clang-format"
        VERBATIM
    )
    
    # Create convenience targets
    add_custom_target(format-all
        DEPENDS w1-format redlog-format
        COMMENT "Formatting all code"
    )
    
    add_custom_target(format-check-all
        DEPENDS w1-format-check redlog-format-check
        COMMENT "Checking all code formatting"
    )
    
    message(STATUS "  - Run 'make w1-format' to format w1tn3ss code")
    message(STATUS "  - Run 'make w1-format-check' to check w1tn3ss formatting")
    message(STATUS "  - Run 'make format-all' to format all code")
    message(STATUS "  - Run 'make format-check-all' to check all code formatting")
else()
    message(WARNING "clang-format not found. Install clang-format to enable code formatting targets.")
endif()