cmake_minimum_required(VERSION 3.16)

include(${W1_SOURCE_DIR}/cmake/TestConfig.cmake)

set(W1BASE_TEST_SOURCES
    ${W1_SOURCE_DIR}/test/common/test_main.cpp
    interval_test.cpp
)

w1_add_doctest_suite(w1base_unit_tests
    SOURCES ${W1BASE_TEST_SOURCES}
    INCLUDE_DIRS
        ${W1_SOURCE_DIR}/src
        ${W1_SOURCE_DIR}/src/third_party
    LIBS
        w1base
    OUTPUT_SUBDIR test/w1base
)
