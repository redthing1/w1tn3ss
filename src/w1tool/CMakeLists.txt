set(EXECUTABLE_NAME w1tool)

set(SOURCES
    main.cpp
)

add_executable(${EXECUTABLE_NAME} ${SOURCES})

# set output directory to be flat
set_target_properties(${EXECUTABLE_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

target_include_directories(${EXECUTABLE_NAME}
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(${EXECUTABLE_NAME}
    PRIVATE
        w1tn3ss
        w1nj3ct
        common
        redlog::redlog
)

target_compile_features(${EXECUTABLE_NAME} PRIVATE cxx_std_17)

# enable sanitizers for main executable in debug builds
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT WIN32)
    target_compile_options(${EXECUTABLE_NAME} PRIVATE ${SANITIZER_FLAGS})
    target_link_options(${EXECUTABLE_NAME} PRIVATE ${SANITIZER_FLAGS})
endif()

install(TARGETS ${EXECUTABLE_NAME}
    RUNTIME DESTINATION bin
)