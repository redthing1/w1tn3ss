cmake_minimum_required(VERSION 3.16)

include(${W1_SOURCE_DIR}/cmake/TestConfig.cmake)

set(W1ASMR_TEST_SOURCES
    test_main.cpp
    asmr_test.cpp
)

w1_add_doctest_suite(w1asmr_tests
    SOURCES ${W1ASMR_TEST_SOURCES}
    INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${W1_SOURCE_DIR}/src
        ${W1_SOURCE_DIR}/src/third_party
    LIBS w1asmr
    OUTPUT_SUBDIR w1asmr
)
