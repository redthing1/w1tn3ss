# test programs for injection testing

# simple target program
add_executable(simple_target simple_target.c)
set_target_properties(simple_target PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/programs
)

# long running target program
add_executable(long_running_target long_running_target.c)
set_target_properties(long_running_target PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/programs
)

# multi-threaded target program
add_executable(multi_threaded_target multi_threaded_target.c)
set_target_properties(multi_threaded_target PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/programs
)

# control flow crackme program
add_executable(control_flow_1 control_flow_1.cpp)
set_target_properties(control_flow_1 PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/programs
)

# standalone coverage test program (disabled - implementation not complete)
# add_executable(test_standalone_coverage test_standalone_coverage.cpp)
# target_link_libraries(test_standalone_coverage PRIVATE w1cov)
# set_target_properties(test_standalone_coverage PROPERTIES
#     RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/programs
# )

# runtime injection target program
add_executable(runtime_injection_target runtime_injection_target.c)
set_target_properties(runtime_injection_target PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/programs
)

# linux-specific target programs
if(UNIX AND NOT APPLE)
    # linux injection target with linux-specific features
    add_executable(linux_target linux_target.c)
    set_target_properties(linux_target PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/programs
    )
    
    # linux daemon target for testing background process injection
    add_executable(linux_daemon linux_daemon.c)
    set_target_properties(linux_daemon PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/programs
    )
endif()

# enable sanitizers for test programs in debug builds
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT WIN32)
    target_compile_options(simple_target PRIVATE ${SANITIZER_FLAGS})
    target_link_options(simple_target PRIVATE ${SANITIZER_FLAGS})
    
    target_compile_options(long_running_target PRIVATE ${SANITIZER_FLAGS})
    target_link_options(long_running_target PRIVATE ${SANITIZER_FLAGS})
    
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
set(PROGRAM_TARGETS simple_target long_running_target multi_threaded_target control_flow_1 runtime_injection_target)

# add linux-specific targets to install list
if(UNIX AND NOT APPLE)
    list(APPEND PROGRAM_TARGETS linux_target linux_daemon)
endif()

install(TARGETS ${PROGRAM_TARGETS}
    RUNTIME DESTINATION tests/programs
)