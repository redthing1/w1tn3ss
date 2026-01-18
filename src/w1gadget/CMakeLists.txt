cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)

add_library(w1gadget STATIC
    gadget_executor.cpp
)

target_include_directories(w1gadget
    PUBLIC $<BUILD_INTERFACE:${WITNESS_SOURCE_DIR}/src>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(w1gadget PUBLIC QBDI_static redlog::redlog)

apply_common_compile_options(w1gadget)
apply_windows_definitions(w1gadget)
set_standard_output_dirs(w1gadget)

set_target_properties(w1gadget PROPERTIES POSITION_INDEPENDENT_CODE ON)
