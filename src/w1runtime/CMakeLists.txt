cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)

add_library(w1runtime STATIC
    module_registry.cpp
    memory_reader.cpp
    register_capture.cpp
    stack_capture.cpp
)

target_include_directories(w1runtime
    PUBLIC $<BUILD_INTERFACE:${WITNESS_SOURCE_DIR}/src>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(w1runtime PUBLIC QBDI_static)

apply_common_compile_options(w1runtime)
apply_windows_definitions(w1runtime)
set_standard_output_dirs(w1runtime)

set_target_properties(w1runtime PROPERTIES POSITION_INDEPENDENT_CODE ON)
