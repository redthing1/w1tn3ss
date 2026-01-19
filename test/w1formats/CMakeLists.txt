cmake_minimum_required(VERSION 3.16)

include(${W1_SOURCE_DIR}/cmake/TestConfig.cmake)

set(W1FORMATS_TEST_SOURCES
    ${W1_SOURCE_DIR}/test/common/test_main.cpp
    jsonl_writer_test.cpp
)

w1_add_doctest_suite(w1formats_unit_tests
    SOURCES ${W1FORMATS_TEST_SOURCES}
    INCLUDE_DIRS
        ${W1_SOURCE_DIR}/src
        ${W1_SOURCE_DIR}/src/third_party
    LIBS
        w1formats
    OUTPUT_SUBDIR w1formats
)
