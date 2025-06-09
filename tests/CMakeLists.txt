# w1nj3ct test suite

# build test programs and libraries
add_subdirectory(programs)
add_subdirectory(libraries)

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

# configure test script template
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/run_injection_tests${TEST_SCRIPT_EXT}.in
    ${CMAKE_BINARY_DIR}/tests/run_injection_tests${TEST_SCRIPT_EXT}
    @ONLY
)

# make script executable on unix
if(UNIX)
    file(CHMOD ${CMAKE_BINARY_DIR}/tests/run_injection_tests.sh
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                   GROUP_READ GROUP_EXECUTE
                   WORLD_READ WORLD_EXECUTE
    )
endif()