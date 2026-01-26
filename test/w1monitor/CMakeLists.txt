cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TestConfig.cmake)

set(W1MONITOR_TEST_SOURCES
    test_main.cpp
    backend_helpers_tests.cpp
    event_queue_tests.cpp
    monitor_tests.cpp
)

if(APPLE)
    list(APPEND W1MONITOR_TEST_SOURCES monitor_tests_darwin.cpp)
elseif(WIN32)
    list(APPEND W1MONITOR_TEST_SOURCES monitor_tests_windows.cpp)
elseif(UNIX)
    list(APPEND W1MONITOR_TEST_SOURCES monitor_tests_linux.cpp)
endif()

w1_add_doctest_suite(w1monitor_tests
    SOURCES ${W1MONITOR_TEST_SOURCES}
    INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${WITNESS_SOURCE_DIR}/test/common
        ${WITNESS_SOURCE_DIR}/src
        ${WITNESS_SOURCE_DIR}/src/third_party
    LIBS w1monitor ${CMAKE_DL_LIBS}
    OUTPUT_SUBDIR w1monitor
)
