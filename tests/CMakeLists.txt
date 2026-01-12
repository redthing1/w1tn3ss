# w1nj3ct test suite

# build test libraries
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

# standalone tracers test program
add_executable(test_standalone_tracers test_standalone_tracers.cpp)
apply_common_compile_options(test_standalone_tracers)
apply_windows_definitions(test_standalone_tracers)
target_include_directories(test_standalone_tracers PRIVATE ${WITNESS_SOURCE_DIR}/src)
target_link_libraries(test_standalone_tracers PRIVATE w1cov_static w1xfer_static w1tn3ss redlog::redlog)

# conditionally link w1script if enabled
if(WITNESS_SCRIPT)
    include(${WITNESS_SOURCE_DIR}/cmake/LuaConfig.cmake)
    configure_target_with_lua(test_standalone_tracers)
    target_link_libraries(test_standalone_tracers PRIVATE w1script_static)
endif()

# apply windows symbol resolution after all libraries are linked
if(WIN32 AND MSVC)
    include(${WITNESS_SOURCE_DIR}/cmake/WindowsSymbolConfig.cmake)
    configure_windows_symbol_resolution(test_standalone_tracers)
endif()

set_target_properties(test_standalone_tracers PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)

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
