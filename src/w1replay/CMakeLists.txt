cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)
include(${WITNESS_SOURCE_DIR}/cmake/LIEFConfig.cmake)

add_executable(w1replay
    main.cpp
    asmr_block_decoder.cpp
    commands/checkpoint.cpp
    commands/inspect.cpp
    commands/threads.cpp
)

set_target_properties(w1replay PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

target_include_directories(w1replay PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${WITNESS_SOURCE_DIR}/src
)

target_link_libraries(w1replay PRIVATE
    w1tn3ss
    common
    redlog::redlog
)

if(TARGET p1ll_asmr)
    target_link_libraries(w1replay PRIVATE p1ll_asmr)
endif()

apply_common_compile_options(w1replay)
apply_windows_definitions(w1replay)
configure_target_with_lief(w1replay)

install(TARGETS w1replay RUNTIME DESTINATION bin)
