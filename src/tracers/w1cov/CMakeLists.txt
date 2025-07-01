# w1cov - Reference Coverage Tracer
cmake_minimum_required(VERSION 3.16)

# w1cov tracer library - can be built as shared or static
if(WITNESS_BUILD_SHARED)
    add_library(w1cov_qbdipreload SHARED
        preload.cpp
        coverage_tracer.cpp
        coverage_collector.cpp
    )
endif()

if(WITNESS_BUILD_STATIC)
    add_library(w1cov_static STATIC
        preload.cpp
        coverage_tracer.cpp
        coverage_collector.cpp
    )
endif()

# Function to configure a w1cov target
function(configure_w1cov_target target_name)
    target_include_directories(${target_name} PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/third_party/qbdi/tools/QBDIPreload/include
    )

    target_link_libraries(${target_name} PRIVATE
        w1tn3ss
        QBDI_static
        redlog::redlog
    )
    
    # Link QBDIPreload for shared library version
    if(${target_name} STREQUAL "w1cov_qbdipreload")
        target_link_libraries(${target_name} PRIVATE QBDIPreload)
    endif()

    target_compile_features(${target_name} PRIVATE cxx_std_17)

    # Set appropriate compiler flags
    target_compile_options(${target_name} PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -O2>
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /O2>
    )

    # Set output directory and remove lib prefix
    set_target_properties(${target_name} PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        PREFIX ""
    )

    # Platform-specific settings
    if(APPLE)
        set_target_properties(${target_name} PROPERTIES
            MACOSX_RPATH TRUE
        )
    elseif(UNIX)
        target_link_libraries(${target_name} PRIVATE dl)
    endif()
endfunction()

# Configure targets
if(WITNESS_BUILD_SHARED)
    configure_w1cov_target(w1cov_qbdipreload)
endif()

if(WITNESS_BUILD_STATIC)
    configure_w1cov_target(w1cov_static)
endif()