cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)

add_library(w1dump STATIC
    memory_dumper.cpp
    process_dumper.cpp
    register_dumper.cpp
)

target_include_directories(w1dump
    PUBLIC $<BUILD_INTERFACE:${WITNESS_SOURCE_DIR}/src>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(w1dump PUBLIC w1formats w1runtime redlog::redlog)

apply_common_compile_options(w1dump)
apply_windows_definitions(w1dump)
set_standard_output_dirs(w1dump)

set_target_properties(w1dump PROPERTIES POSITION_INDEPENDENT_CODE ON)
