cmake_minimum_required(VERSION 3.16)

# Only build on macOS
if(NOT APPLE)
    message(STATUS "insert_dylib skipped on non-apple platform")
    return()
endif()

# Create executable
add_executable(insert_dylib main.cpp)

# Set C++17 standard to match project
set_target_properties(insert_dylib PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    OUTPUT_NAME insert_dylib
)

# Include directories
target_include_directories(insert_dylib PRIVATE
    ${WITNESS_SOURCE_DIR}/src
)

# Link dependencies
target_link_libraries(insert_dylib PRIVATE
    redlog::redlog
    "-framework CoreFoundation"
)

# Apply common compile options (if available)
if(COMMAND apply_common_compile_options)
    apply_common_compile_options(insert_dylib)
endif()

# Install target
install(TARGETS insert_dylib RUNTIME DESTINATION bin)

message(STATUS "insert_dylib tool configured for macOS")