cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TestConfig.cmake)

set(W1ANALYSIS_TEST_SOURCES
    ${WITNESS_SOURCE_DIR}/test/common/test_main.cpp
    abi_dispatcher_test.cpp
    symbol_lookup_test.cpp
)

w1_add_doctest_suite(w1analysis_unit_tests
    SOURCES ${W1ANALYSIS_TEST_SOURCES}
    INCLUDE_DIRS
        ${WITNESS_SOURCE_DIR}/src
        ${WITNESS_SOURCE_DIR}/src/third_party
    LIBS
        w1analysis
    OUTPUT_SUBDIR test/w1analysis
)
