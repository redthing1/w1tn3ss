cmake_minimum_required(VERSION 3.16)

include(${W1_SOURCE_DIR}/cmake/TestConfig.cmake)

set(P1LL_TEST_SOURCES
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

w1_add_doctest_suite(p1ll_unit_tests
    SOURCES ${P1LL_TEST_SOURCES}
    INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${W1_SOURCE_DIR}/src
        ${W1_SOURCE_DIR}/src/third_party
    LIBS p1ll_core
    OUTPUT_SUBDIR test/p1ll/core
)
