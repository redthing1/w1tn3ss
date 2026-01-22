cmake_minimum_required(VERSION 3.16)

include(${W1_SOURCE_DIR}/cmake/TestConfig.cmake)

set(W1H00K_TEST_SOURCES
    test_main.cpp
    reloc_tests.cpp
    patcher_tests.cpp
    memory_tests.cpp
    resolve_tests.cpp
    inline_tests.cpp
    inline_detour_tests.cpp
    arg_access_tests.cpp
    instrument_tests.cpp
    import_table_tests.cpp
    interpose_tests.cpp
)

w1_add_doctest_suite(w1h00k_tests
    SOURCES ${W1H00K_TEST_SOURCES}
    INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${W1_SOURCE_DIR}/src
        ${W1_SOURCE_DIR}/src/third_party
    LIBS w1h00k
    OUTPUT_SUBDIR w1h00k
)
