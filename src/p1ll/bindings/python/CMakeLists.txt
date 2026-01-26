cmake_minimum_required(VERSION 3.15)

project(p1ll_python LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(FetchContent)

get_filename_component(P1LL_SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
get_filename_component(W1TN3SS_ROOT "${P1LL_SOURCE_DIR}/../.." ABSOLUTE)

find_package(Python REQUIRED COMPONENTS Interpreter Development.Module)

set(NB_TEST OFF CACHE BOOL "disable nanobind tests" FORCE)
set(NB_CREATE_INSTALL_RULES OFF CACHE BOOL "disable nanobind install rules" FORCE)
FetchContent_Declare(
    nanobind
    GIT_REPOSITORY https://github.com/wjakob/nanobind.git
    GIT_TAG v2.10.2
    GIT_SUBMODULES_RECURSE ON
)
FetchContent_MakeAvailable(nanobind)

set(WITNESS_BUILD_ALL OFF CACHE BOOL "disable full w1tn3ss build" FORCE)
set(WITNESS_BUILD_P1LL ON CACHE BOOL "build p1ll component" FORCE)
set(WITNESS_SCRIPT OFF CACHE BOOL "disable scripting for standalone p1ll python build" FORCE)
set(P1LL_BUILD_CAPI OFF CACHE BOOL "disable p1ll c api for python build" FORCE)

add_subdirectory("${W1TN3SS_ROOT}" "${CMAKE_BINARY_DIR}/w1tn3ss")

nanobind_add_module(_p1ll
    "${CMAKE_CURRENT_LIST_DIR}/p1ll_python.cpp"
)
target_link_libraries(_p1ll PRIVATE p1ll_core)

set(P1LL_PYTHON_OUTPUT_DIR "${CMAKE_BINARY_DIR}/p1ll")
file(MAKE_DIRECTORY "${P1LL_PYTHON_OUTPUT_DIR}")
set_target_properties(_p1ll PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${P1LL_PYTHON_OUTPUT_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${P1LL_PYTHON_OUTPUT_DIR}"
    ARCHIVE_OUTPUT_DIRECTORY "${P1LL_PYTHON_OUTPUT_DIR}"
)

add_custom_command(TARGET _p1ll POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${CMAKE_CURRENT_LIST_DIR}/p1ll/__init__.py"
            "${P1LL_PYTHON_OUTPUT_DIR}/__init__.py"
)

install(TARGETS _p1ll
    LIBRARY DESTINATION p1ll
    RUNTIME DESTINATION p1ll
    ARCHIVE DESTINATION p1ll
    COMPONENT ${WITNESS_INSTALL_COMPONENT}
)
install(FILES "${CMAKE_CURRENT_LIST_DIR}/p1ll/__init__.py"
    DESTINATION p1ll
    COMPONENT ${WITNESS_INSTALL_COMPONENT}
)
