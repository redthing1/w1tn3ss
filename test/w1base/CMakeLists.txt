cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TestConfig.cmake)

set(W1BASE_TEST_SOURCES
    ${WITNESS_SOURCE_DIR}/test/common/test_main.cpp
    interval_test.cpp
)

w1_add_doctest_suite(w1base_unit_tests
    SOURCES ${W1BASE_TEST_SOURCES}
    INCLUDE_DIRS
        ${WITNESS_SOURCE_DIR}/src
        ${WITNESS_SOURCE_DIR}/src/third_party
    LIBS
        w1base
    OUTPUT_SUBDIR w1base
)
