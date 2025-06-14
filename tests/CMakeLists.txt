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
