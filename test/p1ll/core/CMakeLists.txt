cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)

add_executable(p1ll_unit_tests
    test_main.cpp
    pattern_test.cpp
    pattern_matcher_test.cpp
    scanner_test.cpp
    plan_builder_test.cpp
    apply_test.cpp
    address_space_test.cpp
    platform_test.cpp
    session_test.cpp
)

target_include_directories(p1ll_unit_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${WITNESS_SOURCE_DIR}/src
    ${WITNESS_SOURCE_DIR}/src/third_party
)

target_link_libraries(p1ll_unit_tests PRIVATE
    p1ll_core
)

set_target_properties(p1ll_unit_tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test/p1ll/core
)

apply_common_compile_options(p1ll_unit_tests)
apply_windows_definitions(p1ll_unit_tests)

add_test(
    NAME p1ll_unit_tests
    COMMAND p1ll_unit_tests
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/test/p1ll/core
)
