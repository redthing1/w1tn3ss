cmake_minimum_required(VERSION 3.12)

project(w1tn3ss
    VERSION 0.1.0
    DESCRIPTION "Cross-platform dynamic binary analysis tool"
    LANGUAGES C CXX ASM
)

# build options
option(WITNESS_BUILD_STATIC "Build static libraries" ON)
option(WITNESS_BUILD_SHARED "Build shared libraries" ON)
option(WITNESS_QBDI_EXTRAS "Build QBDI with examples, tests and additional tools" OFF)

# load configuration modules
include(${CMAKE_SOURCE_DIR}/cmake/CommonConfig.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/PlatformConfig.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/LuaConfig.cmake)

# configure platform and architecture
detect_qbdi_platform()
detect_architecture()
configure_qbdi_options()

# print witness configuration block
message(STATUS "")
message(STATUS "== WITNESS Config ==")
message(STATUS "Platform:              ${QBDI_PLATFORM}")
message(STATUS "Architecture:          ${WITNESS_ARCH}")
message(STATUS "Build Type:            ${CMAKE_BUILD_TYPE}")
message(STATUS "Static Libraries:      ${WITNESS_BUILD_STATIC}")
message(STATUS "Shared Libraries:      ${WITNESS_BUILD_SHARED}")
message(STATUS "Scripting Support:     ${WITNESS_SCRIPT}")
message(STATUS "Tests:                 ${BUILD_TESTS}")
message(STATUS "")

# add third-party libraries
add_subdirectory(src/third_party/qbdi)

# configure redlog
set(REDLOG_BUILD_TESTS OFF)
add_subdirectory(src/third_party/redlog_cpp)

# add project subdirectories
add_subdirectory(src/common)
add_subdirectory(src/w1tn3ss)
add_subdirectory(src/tracers)
add_subdirectory(src/w1nj3ct)
add_subdirectory(src/w1tool)

# add tests (optional)
option(BUILD_TESTS "Build test programs and libraries" ON)
if(BUILD_TESTS)
    add_subdirectory(tests)
endif()

# code formatting with clang-format
find_program(CLANG_FORMAT_EXECUTABLE
    NAMES clang-format clang-format-18 clang-format-17 clang-format-16 clang-format-15
    DOC "Path to clang-format executable"
)

if(CLANG_FORMAT_EXECUTABLE)
    message(STATUS "clang-format found: ${CLANG_FORMAT_EXECUTABLE}")
    
    file(GLOB_RECURSE ALL_SOURCE_FILES
        "${CMAKE_SOURCE_DIR}/src/w1tn3ss/*.cpp" "${CMAKE_SOURCE_DIR}/src/w1tn3ss/*.hpp"
        "${CMAKE_SOURCE_DIR}/src/w1nj3ct/*.cpp" "${CMAKE_SOURCE_DIR}/src/w1nj3ct/*.hpp"
        "${CMAKE_SOURCE_DIR}/src/w1tool/*.cpp" "${CMAKE_SOURCE_DIR}/src/w1tool/*.hpp"
        "${CMAKE_SOURCE_DIR}/src/tracers/*.cpp" "${CMAKE_SOURCE_DIR}/src/tracers/*.hpp"
        "${CMAKE_SOURCE_DIR}/src/common/*.cpp" "${CMAKE_SOURCE_DIR}/src/common/*.hpp"
        "${CMAKE_SOURCE_DIR}/tests/*.cpp" "${CMAKE_SOURCE_DIR}/tests/*.hpp"
    )
    
    add_custom_target(w1-format
        COMMAND ${CLANG_FORMAT_EXECUTABLE} -i -style=file ${ALL_SOURCE_FILES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "formatting w1tn3ss code"
        VERBATIM
    )
    
    add_custom_target(w1-format-check
        COMMAND ${CLANG_FORMAT_EXECUTABLE} --dry-run --Werror -style=file ${ALL_SOURCE_FILES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "checking w1tn3ss code formatting"
        VERBATIM
    )
endif()