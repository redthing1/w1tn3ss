cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)

add_library(w1formats STATIC
    jsonl_writer.cpp
)

target_include_directories(w1formats
    PUBLIC $<BUILD_INTERFACE:${WITNESS_SOURCE_DIR}/src>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(w1formats PUBLIC nlohmann_json::nlohmann_json)

apply_common_compile_options(w1formats)
apply_windows_definitions(w1formats)
set_standard_output_dirs(w1formats)

set_target_properties(w1formats PROPERTIES POSITION_INDEPENDENT_CODE ON)
