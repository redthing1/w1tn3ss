cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)

add_library(w1base STATIC
    arch_spec.cpp
    env_config.cpp
    module_identity.cpp
    signal_handler.cpp
)

target_include_directories(w1base
    PUBLIC $<BUILD_INTERFACE:${WITNESS_SOURCE_DIR}/src>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(w1base PUBLIC redlog::redlog)

apply_common_compile_options(w1base)
apply_windows_definitions(w1base)
apply_platform_linking(w1base)
set_standard_output_dirs(w1base)

set_target_properties(w1base PROPERTIES POSITION_INDEPENDENT_CODE ON)
