# p1ll Python bindings (nanobind)

set(NB_TEST OFF CACHE BOOL "nanobind tests" FORCE)
set(NB_CREATE_INSTALL_RULES OFF CACHE BOOL "nanobind install rules" FORCE)
set(NB_USE_SUBMODULE_DEPS ON CACHE BOOL "nanobind submodule deps" FORCE)

if(NOT TARGET nanobind-static)
    add_subdirectory(${WITNESS_SOURCE_DIR}/src/third_party/nanobind
        ${CMAKE_CURRENT_BINARY_DIR}/nanobind
        EXCLUDE_FROM_ALL
    )
endif()

find_package(Python REQUIRED COMPONENTS Interpreter Development.Module)

set(P1LL_PYTHON_SOURCES
    p1ll_python.cpp
)

nanobind_add_module(p1ll_python
    NB_STATIC
    NOMINSIZE
    ${P1LL_PYTHON_SOURCES}
)

target_link_libraries(p1ll_python PRIVATE p1ll_core)

target_compile_features(p1ll_python PRIVATE cxx_std_20)

set(P1LL_PYTHON_OUTPUT_DIR ${CMAKE_BINARY_DIR}/python/p1ll)
file(MAKE_DIRECTORY ${P1LL_PYTHON_OUTPUT_DIR})

set_target_properties(p1ll_python PROPERTIES
    OUTPUT_NAME "_p1ll"
    LIBRARY_OUTPUT_DIRECTORY ${P1LL_PYTHON_OUTPUT_DIR}
    RUNTIME_OUTPUT_DIRECTORY ${P1LL_PYTHON_OUTPUT_DIR}
    ARCHIVE_OUTPUT_DIRECTORY ${P1LL_PYTHON_OUTPUT_DIR}
)

add_custom_command(TARGET p1ll_python POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_SOURCE_DIR}/p1ll/__init__.py
        ${P1LL_PYTHON_OUTPUT_DIR}/__init__.py
)

if(SKBUILD)
    install(TARGETS p1ll_python LIBRARY DESTINATION ${SKBUILD_PLATLIB_DIR}/p1ll)
    install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/p1ll
        DESTINATION ${SKBUILD_PLATLIB_DIR}
        FILES_MATCHING PATTERN "*.py"
    )
endif()
