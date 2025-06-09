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

# injection libraries must not depend on sanitizers
# target processes may not have asan initialized
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT WIN32)
    target_compile_options(tracer_lib PRIVATE -fno-sanitize=all)
    target_link_options(tracer_lib PRIVATE -fno-sanitize=all)
    
    target_compile_options(counter_lib PRIVATE -fno-sanitize=all)
    target_link_options(counter_lib PRIVATE -fno-sanitize=all)
    
    target_compile_options(memory_lib PRIVATE -fno-sanitize=all)
    target_link_options(memory_lib PRIVATE -fno-sanitize=all)
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
endif()

# install targets
install(TARGETS tracer_lib counter_lib memory_lib
    LIBRARY DESTINATION tests/libraries
    RUNTIME DESTINATION tests/libraries
)