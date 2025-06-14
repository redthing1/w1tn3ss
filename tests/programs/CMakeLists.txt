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
endif()

# platform-specific linking
if(WIN32)
    # no additional libraries needed for Windows
elseif(UNIX)
    # link pthread for unix systems
    target_link_libraries(multi_threaded_target PRIVATE pthread)
endif()

# install targets
install(TARGETS simple_target long_running_target multi_threaded_target control_flow_1
    RUNTIME DESTINATION tests/programs
)