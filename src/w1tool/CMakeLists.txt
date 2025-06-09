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

install(TARGETS ${EXECUTABLE_NAME}
    RUNTIME DESTINATION bin
)