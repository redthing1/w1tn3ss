# test programs for injection testing


# multi-threaded target program
add_executable(multi_threaded_target multi_threaded_target.c)
apply_common_compile_options(multi_threaded_target)
apply_windows_definitions(multi_threaded_target)
set_target_properties(multi_threaded_target PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/programs
)

# control flow crackme program
add_executable(control_flow_1 control_flow_1.cpp)
apply_common_compile_options(control_flow_1)
apply_windows_definitions(control_flow_1)
set_target_properties(control_flow_1 PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/programs
)

# standalone coverage test program
add_executable(test_standalone_coverage test_standalone_coverage.cpp)
apply_common_compile_options(test_standalone_coverage)
apply_windows_definitions(test_standalone_coverage)
target_include_directories(test_standalone_coverage PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_standalone_coverage PRIVATE w1cov_static w1tn3ss QBDI_static redlog::redlog)
set_target_properties(test_standalone_coverage PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/programs
)

# runtime injection target program
add_executable(runtime_injection_target runtime_injection_target.c)
apply_common_compile_options(runtime_injection_target)
apply_windows_definitions(runtime_injection_target)
set_target_properties(runtime_injection_target PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/programs
)

# simple demo program for script testing
add_executable(simple_demo simple_demo.c)
apply_common_compile_options(simple_demo)
apply_windows_definitions(simple_demo)
set_target_properties(simple_demo PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/programs
)

# linux-specific target programs
if(UNIX AND NOT APPLE)
    # linux injection target with linux-specific features
    add_executable(linux_target linux_target.c)
    apply_common_compile_options(linux_target)
    apply_windows_definitions(linux_target)
    set_target_properties(linux_target PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/programs
    )
    
    # linux daemon target for testing background process injection
    add_executable(linux_daemon linux_daemon.c)
    apply_common_compile_options(linux_daemon)
    apply_windows_definitions(linux_daemon)
    set_target_properties(linux_daemon PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/programs
    )
endif()

# enable sanitizers for test programs in debug builds
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT WIN32)
    target_compile_options(multi_threaded_target PRIVATE ${SANITIZER_FLAGS})
    target_link_options(multi_threaded_target PRIVATE ${SANITIZER_FLAGS})
    
    target_compile_options(control_flow_1 PRIVATE ${SANITIZER_FLAGS})
    target_link_options(control_flow_1 PRIVATE ${SANITIZER_FLAGS})
    
    target_compile_options(runtime_injection_target PRIVATE ${SANITIZER_FLAGS})
    target_link_options(runtime_injection_target PRIVATE ${SANITIZER_FLAGS})
    
    # linux-specific targets
    if(UNIX AND NOT APPLE)
        target_compile_options(linux_target PRIVATE ${SANITIZER_FLAGS})
        target_link_options(linux_target PRIVATE ${SANITIZER_FLAGS})
        
        target_compile_options(linux_daemon PRIVATE ${SANITIZER_FLAGS})
        target_link_options(linux_daemon PRIVATE ${SANITIZER_FLAGS})
    endif()
endif()

# platform-specific linking
if(WIN32)
    # no additional libraries needed for Windows
elseif(UNIX)
    # link pthread for unix systems
    target_link_libraries(multi_threaded_target PRIVATE pthread)
    target_link_libraries(runtime_injection_target PRIVATE pthread)
endif()

# install targets
set(PROGRAM_TARGETS multi_threaded_target control_flow_1 runtime_injection_target simple_demo)

# add linux-specific targets to install list
if(UNIX AND NOT APPLE)
    list(APPEND PROGRAM_TARGETS linux_target linux_daemon)
endif()

install(TARGETS ${PROGRAM_TARGETS}
    RUNTIME DESTINATION tests/programs
)