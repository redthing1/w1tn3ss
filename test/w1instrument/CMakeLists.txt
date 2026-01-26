cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TestConfig.cmake)

set(W1INSTRUMENT_TEST_SOURCES
    ${WITNESS_SOURCE_DIR}/test/common/test_main.cpp
    event_router_test.cpp
    instrumentation_policy_test.cpp
    thread_session_simple_test.cpp
)

w1_add_doctest_suite(w1instrument_unit_tests
    SOURCES ${W1INSTRUMENT_TEST_SOURCES}
    INCLUDE_DIRS
        ${WITNESS_SOURCE_DIR}/src
        ${WITNESS_SOURCE_DIR}/src/third_party
    LIBS
        w1instrument
    OUTPUT_SUBDIR w1instrument
)
