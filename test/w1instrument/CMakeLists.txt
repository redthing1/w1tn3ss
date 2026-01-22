cmake_minimum_required(VERSION 3.16)

include(${W1_SOURCE_DIR}/cmake/TestConfig.cmake)

set(W1INSTRUMENT_TEST_SOURCES
    ${W1_SOURCE_DIR}/test/common/test_main.cpp
    event_router_test.cpp
    instrumentation_policy_test.cpp
    vm_session_simple_test.cpp
)

w1_add_doctest_suite(w1instrument_unit_tests
    SOURCES ${W1INSTRUMENT_TEST_SOURCES}
    INCLUDE_DIRS
        ${W1_SOURCE_DIR}/src
        ${W1_SOURCE_DIR}/src/third_party
    LIBS
        w1instrument
    OUTPUT_SUBDIR w1instrument
)
