# w1nj3ct test suite

# build test programs and libraries
add_subdirectory(programs)
add_subdirectory(libraries)

# enable CMake testing framework
enable_testing()

# create test runner script
if(WIN32)
    set(TEST_SCRIPT_EXT ".bat")
    set(LIB_EXT ".dll")
else()
    set(TEST_SCRIPT_EXT ".sh")
    if(APPLE)
        set(LIB_EXT ".dylib")
    else()
        set(LIB_EXT ".so")
    endif()
endif()

# add p1ll pattern matching unit tests
if(WITNESS_SCRIPT)
    add_test(
        NAME p1ll_pattern_matching_tests
        COMMAND test_p1ll_pattern_matching
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/tests/programs
    )
    set_tests_properties(p1ll_pattern_matching_tests PROPERTIES
        LABELS "unit;p1ll;pattern_matching"
    )
endif()
