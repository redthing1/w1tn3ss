cmake_minimum_required(VERSION 3.12)

project(w1tn3ss
    VERSION 0.1.0
    DESCRIPTION "Cross-platform dynamic binary analysis tool"
    LANGUAGES C CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# default to debug build
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# sanitizers disabled - cause crashes with QBDI injection
# if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT WIN32)
#     set(SANITIZER_FLAGS "-fsanitize=address;-fsanitize=undefined")
# endif()

# options
option(WITNESS_SHARED "Build w1tn3ss as shared library" ON)
option(WITNESS_QBDI_EXTRAS "Build QBDI with examples, tests and additional tools" OFF)

# auto-detect qbdi platform and architecture
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(QBDI_PLATFORM "linux")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(QBDI_PLATFORM "osx")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(QBDI_PLATFORM "windows")
else()
    message(FATAL_ERROR "Unsupported platform for QBDI: ${CMAKE_SYSTEM_NAME}")
endif()

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64")
    set(QBDI_ARCH "X86_64")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "i386" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "i686")
    set(QBDI_ARCH "X86")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
    set(QBDI_ARCH "AARCH64")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm")
    set(QBDI_ARCH "ARM")
else()
    message(FATAL_ERROR "Unsupported architecture for QBDI: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

message(STATUS "QBDI Platform: ${QBDI_PLATFORM}")
message(STATUS "QBDI Architecture: ${QBDI_ARCH}")

# configure qbdi
set(QBDI_STATIC_LIBRARY ON)
set(QBDI_LOG_DEBUG OFF)

if(WITNESS_QBDI_EXTRAS)
    set(QBDI_TOOLS_PYQBDI ON)
    set(QBDI_TOOLS_FRIDAQBDI ON)
    set(QBDI_TEST ON)
    set(QBDI_EXAMPLES ON)
else()
    set(QBDI_TOOLS_PYQBDI OFF)
    set(QBDI_TOOLS_FRIDAQBDI OFF)
    set(QBDI_TEST OFF)
    set(QBDI_EXAMPLES OFF)
endif()

# add third-party libraries
add_subdirectory(src/third_party/qbdi)

# configure redlog - disable examples and tests for cleaner build
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