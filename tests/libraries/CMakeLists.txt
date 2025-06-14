# test injection libraries

# tracer library - basic injection verification
add_library(tracer_lib SHARED tracer_lib.c)
set_target_properties(tracer_lib PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/libraries
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/libraries
    PREFIX ""  # no lib prefix
)

# counter library - demonstrates exported functions
add_library(counter_lib SHARED counter_lib.c)
set_target_properties(counter_lib PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/libraries
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/libraries
    PREFIX ""  # no lib prefix
)

# memory tracking library - demonstrates system API usage
add_library(memory_lib SHARED memory_lib.c)
set_target_properties(memory_lib PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/libraries
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/libraries
    PREFIX ""  # no lib prefix
)

# linux-specific test library
if(UNIX AND NOT APPLE)
    add_library(linux_test_lib SHARED linux_test_lib.c)
    set_target_properties(linux_test_lib PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/libraries
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/libraries
        PREFIX ""  # no lib prefix
    )
    target_link_libraries(linux_test_lib PRIVATE ${CMAKE_DL_LIBS})
endif()

# injection libraries must not depend on sanitizers
# target processes may not have asan initialized
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT WIN32)
    target_compile_options(tracer_lib PRIVATE -fno-sanitize=all)
    target_link_options(tracer_lib PRIVATE -fno-sanitize=all)
    
    target_compile_options(counter_lib PRIVATE -fno-sanitize=all)
    target_link_options(counter_lib PRIVATE -fno-sanitize=all)
    
    target_compile_options(memory_lib PRIVATE -fno-sanitize=all)
    target_link_options(memory_lib PRIVATE -fno-sanitize=all)
    
    # linux-specific library
    if(UNIX AND NOT APPLE)
        target_compile_options(linux_test_lib PRIVATE -fno-sanitize=all)
        target_link_options(linux_test_lib PRIVATE -fno-sanitize=all)
    endif()
endif()

# platform-specific linking
if(WIN32)
    target_link_libraries(memory_lib PRIVATE psapi)
    
    # set proper DLL extension
    set_target_properties(tracer_lib PROPERTIES SUFFIX ".dll")
    set_target_properties(counter_lib PROPERTIES SUFFIX ".dll")
    set_target_properties(memory_lib PROPERTIES SUFFIX ".dll")
elseif(APPLE)
    # set proper dylib extension
    set_target_properties(tracer_lib PROPERTIES SUFFIX ".dylib")
    set_target_properties(counter_lib PROPERTIES SUFFIX ".dylib")
    set_target_properties(memory_lib PROPERTIES SUFFIX ".dylib")
else()
    # linux - set proper so extension
    set_target_properties(tracer_lib PROPERTIES SUFFIX ".so")
    set_target_properties(counter_lib PROPERTIES SUFFIX ".so")
    set_target_properties(memory_lib PROPERTIES SUFFIX ".so")
    
    # linux-specific library
    if(TARGET linux_test_lib)
        set_target_properties(linux_test_lib PROPERTIES SUFFIX ".so")
    endif()
endif()

# install targets
set(LIBRARY_TARGETS tracer_lib counter_lib memory_lib)

# add linux-specific targets to install list
if(UNIX AND NOT APPLE)
    list(APPEND LIBRARY_TARGETS linux_test_lib)
endif()

install(TARGETS ${LIBRARY_TARGETS}
    LIBRARY DESTINATION tests/libraries
    RUNTIME DESTINATION tests/libraries
)