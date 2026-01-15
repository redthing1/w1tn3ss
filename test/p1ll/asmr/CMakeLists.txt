cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TestConfig.cmake)

set(P1LL_ASMR_TEST_SOURCES
    test_main.cpp
    asmr_test.cpp
)

w1_add_doctest_suite(p1ll_asmr_tests
    SOURCES ${P1LL_ASMR_TEST_SOURCES}
    INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${WITNESS_SOURCE_DIR}/src
        ${WITNESS_SOURCE_DIR}/src/third_party
    LIBS p1ll_asmr
    OUTPUT_SUBDIR test/p1ll/asmr
)
