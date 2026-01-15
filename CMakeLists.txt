cmake_minimum_required(VERSION 3.12)

project(w1tn3ss
    VERSION 0.1.0
    DESCRIPTION "Cross-platform dynamic binary analysis tool"
    LANGUAGES C CXX ASM
)

# Set witness source directory for both standalone and subdirectory builds
if(NOT DEFINED WITNESS_SOURCE_DIR)
    set(WITNESS_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
endif()

# build options
option(WITNESS_BUILD_STATIC "Build static libraries" ON)
option(WITNESS_BUILD_SHARED "Build shared libraries" ON)
option(WITNESS_QBDI_EXTRAS "Build QBDI with examples, tests and additional tools" OFF)

# load configuration modules
include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)
include(${WITNESS_SOURCE_DIR}/cmake/PlatformConfig.cmake)
include(${WITNESS_SOURCE_DIR}/cmake/LuaConfig.cmake)
include(${WITNESS_SOURCE_DIR}/cmake/JavaScriptConfig.cmake)
include(${WITNESS_SOURCE_DIR}/cmake/LIEFConfig.cmake)
include(${WITNESS_SOURCE_DIR}/cmake/WindowsSymbolConfig.cmake)

# configure platform and architecture
detect_qbdi_platform()
detect_architecture()
configure_qbdi_options()

# setup scripting environments once globally
setup_lua_environment()

# setup lief environment once globally
setup_lief_environment()

# print witness configuration block
message(STATUS "")
message(STATUS "== WITNESS Config ==")
message(STATUS "Platform:              ${QBDI_PLATFORM}")
message(STATUS "Architecture:          ${WITNESS_ARCH}")
message(STATUS "Build Type:            ${CMAKE_BUILD_TYPE}")
message(STATUS "Static Libraries:      ${WITNESS_BUILD_STATIC}")
message(STATUS "Shared Libraries:      ${WITNESS_BUILD_SHARED}")
message(STATUS "Scripting Support:     ${WITNESS_SCRIPT}")
if(WITNESS_SCRIPT)
    message(STATUS "Script Engine:         ${WITNESS_SCRIPT_ENGINE}")
endif()
message(STATUS "LIEF Support:          ${WITNESS_LIEF}")
message(STATUS "Tests:                 ${BUILD_TESTS}")
message(STATUS "")

# configure qbdi to build as static-only (no shared library)
set(QBDI_SHARED_LIBRARY OFF CACHE BOOL "build qbdi shared library" FORCE)
set(QBDI_STATIC_LIBRARY ON CACHE BOOL "build qbdi static library" FORCE)
set(QBDI_EXAMPLES OFF CACHE BOOL "compile qbdi examples" FORCE)
set(QBDI_TEST OFF CACHE BOOL "compile qbdi tests" FORCE)
set(QBDI_BENCHMARK OFF CACHE BOOL "compile qbdi benchmark" FORCE)
message(STATUS "forcing qbdi static-only build")

# add third-party libraries
set(CMAKE_WARN_DEPRECATED OFF)
add_subdirectory(src/third_party/qbdi)
set(CMAKE_WARN_DEPRECATED ON)

# force qbdi targets to use c++17 to avoid c++20 compatibility issues
get_directory_property(QBDI_TARGETS DIRECTORY src/third_party/qbdi BUILDSYSTEM_TARGETS)
message(STATUS "QBDI targets found: ${QBDI_TARGETS}")
foreach(target ${QBDI_TARGETS})
    if(TARGET ${target})
        set_property(TARGET ${target} PROPERTY CXX_STANDARD 17)
        set_property(TARGET ${target} PROPERTY CXX_STANDARD_REQUIRED ON)
        message(STATUS "  - Set ${target} to C++17")
    endif()
endforeach()

# configure redlog
if(NOT TARGET redlog::redlog)
    set(REDLOG_BUILD_TESTS OFF)
    add_subdirectory(src/third_party/redlog_cpp)
endif()

# configure jnjs for javascript support
if(WITNESS_SCRIPT AND WITNESS_SCRIPT_ENGINE STREQUAL "js")
    if(NOT TARGET jnjs)
        set(JNJS_ENABLE_TESTING OFF)
        add_subdirectory(src/third_party/jnjs)
        message(STATUS "added jnjs javascript engine")
    endif()
endif()

# configure nlohmann_json
if(NOT TARGET nlohmann_json::nlohmann_json)
    set(JSON_BuildTests OFF)
    add_subdirectory(src/third_party/nlohmann_json)
endif()

# configure plthook
if(NOT TARGET plthook::plthook)
    option(PLTHOOK_BUILD_TESTS "Build plthook tests" OFF)
    add_subdirectory(src/third_party/plthook)
endif()

# configure funchook
if(WIN32 AND NOT TARGET funchook::funchook)
    set(FUNCHOOK_BUILD_TESTS OFF CACHE BOOL "Build funchook tests" FORCE)
    set(FUNCHOOK_BUILD_SHARED OFF CACHE BOOL "Build funchook shared library" FORCE)
    set(FUNCHOOK_BUILD_STATIC ON CACHE BOOL "Build funchook static library" FORCE)
    add_subdirectory(src/third_party/funchook)
    if(TARGET funchook-static)
        add_library(funchook::funchook ALIAS funchook-static)
    elseif(TARGET funchook-shared)
        add_library(funchook::funchook ALIAS funchook-shared)
    endif()
endif()

# add lief if enabled
if(WITNESS_LIEF)
    add_subdirectory(src/third_party/lief)
    
    # force lief targets to use c++17 as well
    get_directory_property(LIEF_TARGETS DIRECTORY src/third_party/lief BUILDSYSTEM_TARGETS)
    message(STATUS "LIEF targets found: ${LIEF_TARGETS}")
    foreach(target ${LIEF_TARGETS})
        if(TARGET ${target})
            set_property(TARGET ${target} PROPERTY CXX_STANDARD 17)
            set_property(TARGET ${target} PROPERTY CXX_STANDARD_REQUIRED ON)
            message(STATUS "  - Set ${target} to C++17")
        endif()
    endforeach()
endif()

# add project subdirectories
add_subdirectory(src/w1common)
add_subdirectory(src/w1tn3ss)
add_subdirectory(src/tracers)
add_subdirectory(src/w1nj3ct)
add_subdirectory(src/w1debugger)
add_subdirectory(src/w1tool)
add_subdirectory(src/p1ll)
add_subdirectory(src/p1llx)
add_subdirectory(src/p01s0n)

# setup global include directories for clean project-based includes
# this allows includes like <w1common/platform_utils.hpp> instead of ../common/platform_utils.hpp
include_directories(${WITNESS_SOURCE_DIR}/src)

# add tests (optional)
option(BUILD_TESTS "Build test programs and libraries" ON)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(test/w1tn3ss)
    add_subdirectory(test/p1ll)
    add_subdirectory(samples)
    add_subdirectory(tests)
endif()

# apply windows-specific symbol resolution for duplicate symbol conflicts
if(WIN32 AND MSVC)
    apply_windows_symbol_resolution_to_all()
endif()

# code formatting and analysis
include(cmake/FormattingConfig.cmake)
include(cmake/TidyConfig.cmake)
