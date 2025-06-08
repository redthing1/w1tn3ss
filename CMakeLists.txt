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

# add asan and ubsan in debug mode
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(NOT WIN32)
        add_compile_options(-fsanitize=address -fsanitize=undefined)
        add_link_options(-fsanitize=address -fsanitize=undefined)
    endif()
endif()

# options
option(WITNESS_SHARED "Build w1tn3ss as shared library" ON)

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
set(QBDI_TOOLS_PYQBDI OFF)
set(QBDI_TOOLS_FRIDAQBDI ON)
set(QBDI_TEST OFF)

# add qbdi subdirectory
add_subdirectory(src/third_party/qbdi)

# add project subdirectories
add_subdirectory(src/common)
add_subdirectory(src/w1tn3ss)
add_subdirectory(src/w1tool)