# w1tn3ss Framework Static Library
cmake_minimum_required(VERSION 3.16)

# w1tn3ss static library
add_library(w1tn3ss STATIC
    util/env_config.cpp
    util/module_discovery.cpp
)

target_include_directories(w1tn3ss PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(w1tn3ss PUBLIC
    QBDI_static
    redlog::redlog
)

target_compile_features(w1tn3ss PUBLIC cxx_std_17)

# Set appropriate compiler flags
target_compile_options(w1tn3ss PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -O2>
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /O2>
)

# Set output directory
set_target_properties(w1tn3ss PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

# Platform-specific settings
if(UNIX AND NOT APPLE)
    target_link_libraries(w1tn3ss PUBLIC dl)
endif()
