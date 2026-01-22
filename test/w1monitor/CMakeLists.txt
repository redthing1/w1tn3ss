cmake_minimum_required(VERSION 3.16)

include(${W1_SOURCE_DIR}/cmake/TestConfig.cmake)

set(W1MONITOR_TEST_SOURCES
    test_main.cpp
    event_queue_tests.cpp
    monitor_tests.cpp
)

w1_add_doctest_suite(w1monitor_tests
    SOURCES ${W1MONITOR_TEST_SOURCES}
    INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${W1_SOURCE_DIR}/test/common
        ${W1_SOURCE_DIR}/src
        ${W1_SOURCE_DIR}/src/third_party
    LIBS w1monitor ${CMAKE_DL_LIBS}
    OUTPUT_SUBDIR w1monitor
)
