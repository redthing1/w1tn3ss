cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)

add_executable(p1ll_asmr_tests
    test_main.cpp
    asmr_test.cpp
)

target_include_directories(p1ll_asmr_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${WITNESS_SOURCE_DIR}/src
    ${WITNESS_SOURCE_DIR}/src/third_party
)

target_link_libraries(p1ll_asmr_tests PRIVATE
    p1ll_asmr
)

set_target_properties(p1ll_asmr_tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test/p1ll/asmr
)

apply_common_compile_options(p1ll_asmr_tests)
apply_windows_definitions(p1ll_asmr_tests)

add_test(
    NAME p1ll_asmr_tests
    COMMAND p1ll_asmr_tests
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/test/p1ll/asmr
)
