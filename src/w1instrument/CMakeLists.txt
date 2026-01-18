cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)

add_library(w1instrument STATIC
    core/instrumentation_policy.cpp
    core/vm_controller.cpp
)

target_include_directories(w1instrument
    PUBLIC $<BUILD_INTERFACE:${WITNESS_SOURCE_DIR}/src>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(w1instrument PUBLIC w1runtime w1base)

apply_common_compile_options(w1instrument)
apply_windows_definitions(w1instrument)
set_standard_output_dirs(w1instrument)

set_target_properties(w1instrument PROPERTIES POSITION_INDEPENDENT_CODE ON)
