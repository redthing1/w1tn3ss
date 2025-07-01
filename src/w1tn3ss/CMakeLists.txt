cmake_minimum_required(VERSION 3.16)

include(${CMAKE_SOURCE_DIR}/cmake/CommonConfig.cmake)

add_library(w1tn3ss STATIC
    util/env_config.cpp
    util/module_discovery.cpp
    util/module_scanner.cpp
    util/module_range_index.cpp
)

target_include_directories(w1tn3ss PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(w1tn3ss PUBLIC
    QBDI_static
    redlog::redlog
)

apply_common_compile_options(w1tn3ss)
set_standard_output_dirs(w1tn3ss)
apply_platform_linking(w1tn3ss)
