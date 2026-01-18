cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)

add_library(w1analysis STATIC
    abi_dispatcher.cpp
    symbol_lookup.cpp
)

target_include_directories(w1analysis
    PUBLIC $<BUILD_INTERFACE:${WITNESS_SOURCE_DIR}/src>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(w1analysis PUBLIC w1runtime)

if(UNIX AND NOT APPLE)
    target_link_libraries(w1analysis PRIVATE dl)
endif()

apply_common_compile_options(w1analysis)
apply_windows_definitions(w1analysis)
set_standard_output_dirs(w1analysis)

set_target_properties(w1analysis PROPERTIES POSITION_INDEPENDENT_CODE ON)
