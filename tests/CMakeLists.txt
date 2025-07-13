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

# gadget executor test
add_executable(test_gadget_executor test_gadget_executor.cpp)
apply_common_compile_options(test_gadget_executor)
apply_windows_definitions(test_gadget_executor)
target_include_directories(test_gadget_executor PRIVATE ${WITNESS_SOURCE_DIR}/src)
target_link_libraries(test_gadget_executor PRIVATE w1tn3ss QBDI_static redlog::redlog)
set_target_properties(test_gadget_executor PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)

add_test(
    NAME gadget_executor_tests
    COMMAND test_gadget_executor
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)
set_tests_properties(gadget_executor_tests PROPERTIES
    LABELS "unit;gadget;executor"
)
