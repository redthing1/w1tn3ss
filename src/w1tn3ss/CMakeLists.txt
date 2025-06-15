set(LIBRARY_NAME w1tn3ss)

# Create main w1tn3ss library sources
set(SOURCES
    w1tn3ss.cpp
    coverage/coverage_data.cpp
    coverage/module_mapper.cpp
    coverage/w1cov_tracer.cpp
)

set(HEADERS
    w1tn3ss.hpp
    coverage/coverage_data.hpp
    coverage/module_mapper.hpp
    coverage/w1cov_tracer.hpp
    formats/drcov.hpp
)

# Create w1tn3ss library targets based on options
set(W1TN3SS_TARGETS)

if(WITNESS_BUILD_STATIC)
    add_library(${LIBRARY_NAME}_static STATIC ${SOURCES})
    list(APPEND W1TN3SS_TARGETS ${LIBRARY_NAME}_static)
endif()

if(WITNESS_BUILD_SHARED)
    add_library(${LIBRARY_NAME}_shared SHARED ${SOURCES})
    # Configure shared library with export/import declarations
    target_compile_definitions(${LIBRARY_NAME}_shared PRIVATE W1TN3SS_EXPORTS)
    target_compile_definitions(${LIBRARY_NAME}_shared INTERFACE W1TN3SS_IMPORTS)
    list(APPEND W1TN3SS_TARGETS ${LIBRARY_NAME}_shared)
endif()

# Create alias for backwards compatibility
if(WITNESS_BUILD_SHARED)
    add_library(${LIBRARY_NAME} ALIAS ${LIBRARY_NAME}_shared)
elseif(WITNESS_BUILD_STATIC)
    add_library(${LIBRARY_NAME} ALIAS ${LIBRARY_NAME}_static)
else()
    message(FATAL_ERROR "At least one of WITNESS_BUILD_STATIC or WITNESS_BUILD_SHARED must be ON")
endif()

# Set target properties for enabled libraries
if(WITNESS_BUILD_STATIC)
    set_target_properties(${LIBRARY_NAME}_static PROPERTIES
        PUBLIC_HEADER "${HEADERS}"
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
        PREFIX ""
        OUTPUT_NAME "w1tn3ss_static"
    )
endif()

if(WITNESS_BUILD_SHARED)
    set_target_properties(${LIBRARY_NAME}_shared PROPERTIES
        PUBLIC_HEADER "${HEADERS}"
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
        PREFIX ""
        OUTPUT_NAME "w1tn3ss"
    )
endif()

# For Windows multi-config generators, ensure import library is accessible
if(WIN32)
    if(WITNESS_BUILD_STATIC)
        set_target_properties(${LIBRARY_NAME}_static PROPERTIES
            ARCHIVE_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/Debug
            ARCHIVE_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/Release
        )
    endif()
    if(WITNESS_BUILD_SHARED)
        set_target_properties(${LIBRARY_NAME}_shared PROPERTIES
            ARCHIVE_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/Debug
            ARCHIVE_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/Release
            LIBRARY_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/Debug  
            LIBRARY_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/Release
            RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/Debug
            RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/Release
        )
    endif()
endif()

# Include directories for enabled targets
foreach(target ${W1TN3SS_TARGETS})
    target_include_directories(${target}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
            $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
            $<INSTALL_INTERFACE:include>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
    )
endforeach()

# Link libraries for enabled targets
foreach(target ${W1TN3SS_TARGETS})
    target_link_libraries(${target}
        PUBLIC
            QBDI
            common
            redlog::redlog
    )
endforeach()

# Compiler flags for enabled targets
foreach(target ${W1TN3SS_TARGETS})
    target_compile_features(${target} PUBLIC cxx_std_17)
endforeach()

# Sanitizers disabled by default
# if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT WIN32)
#     target_compile_options(${LIBRARY_NAME} PRIVATE ${SANITIZER_FLAGS})
#     target_link_options(${LIBRARY_NAME} PRIVATE ${SANITIZER_FLAGS})
# endif()

if(WIN32)
    foreach(target ${W1TN3SS_TARGETS})
        target_compile_definitions(${target} PRIVATE
            _WIN32_WINNT=0x0601  # Windows 7+
            NOMINMAX
            WIN32_LEAN_AND_MEAN
            _CRT_SECURE_NO_WARNINGS
        )
    endforeach()
endif()

# W1COV coverage library using QBDIPreload
add_library(w1cov_qbdipreload SHARED
    coverage/w1cov_qbdipreload.cpp
)

set_target_properties(w1cov_qbdipreload PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    PREFIX ""
    OUTPUT_NAME "w1cov_qbdipreload"
)

target_include_directories(w1cov_qbdipreload
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src/third_party/qbdi/tools/QBDIPreload/include
)

target_link_libraries(w1cov_qbdipreload
    PRIVATE
        QBDIPreload
        QBDI_static
        redlog::redlog
)

target_compile_features(w1cov_qbdipreload PRIVATE cxx_std_17)

# Windows compile definitions for coverage libraries
if(WIN32)
    target_compile_definitions(w1cov_qbdipreload PRIVATE
        _WIN32_WINNT=0x0601
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        _CRT_SECURE_NO_WARNINGS
    )
endif()


# Runtime injection coverage library
add_library(w1cov_runtime SHARED
    coverage/w1cov_runtime.cpp
)

set_target_properties(w1cov_runtime PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    PREFIX ""
    OUTPUT_NAME "w1cov_runtime"
)

target_include_directories(w1cov_runtime
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(w1cov_runtime
    PRIVATE
        QBDI
        redlog::redlog
)

target_compile_features(w1cov_runtime PRIVATE cxx_std_17)

if(WIN32)
    target_compile_definitions(w1cov_runtime PRIVATE
        _WIN32_WINNT=0x0601
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        _CRT_SECURE_NO_WARNINGS
    )
endif()

# Sampling-based runtime coverage library
add_library(w1cov_sampling SHARED
    coverage/w1cov_sampling.cpp
)

set_target_properties(w1cov_sampling PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    PREFIX ""
    OUTPUT_NAME "w1cov_sampling"
)

target_include_directories(w1cov_sampling
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(w1cov_sampling
    PRIVATE
        QBDI
        redlog::redlog
)

target_compile_features(w1cov_sampling PRIVATE cxx_std_17)

if(WIN32)
    target_compile_definitions(w1cov_sampling PRIVATE
        _WIN32_WINNT=0x0601
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        _CRT_SECURE_NO_WARNINGS
    )
endif()

# Standalone QBDI coverage library
set(W1COV_COMMON_SOURCES
    coverage/common/w1cov_config.cpp
    coverage/common/w1cov_qbdi_utils.cpp
    coverage/common/w1cov_export.cpp
)

set(W1COV_STANDALONE_SOURCES
    ${W1COV_COMMON_SOURCES}
    coverage/coverage_data.cpp
    coverage/module_mapper.cpp
    coverage/w1cov_standalone.cpp
)

add_library(w1cov SHARED ${W1COV_STANDALONE_SOURCES})

set_target_properties(w1cov PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    PREFIX ""
    OUTPUT_NAME "w1cov"
)

target_include_directories(w1cov
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(w1cov
    PRIVATE
        QBDI
        common
        redlog::redlog
)

target_compile_features(w1cov PRIVATE cxx_std_17)

if(WIN32)
    target_compile_definitions(w1cov PRIVATE
        _WIN32_WINNT=0x0601
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        _CRT_SECURE_NO_WARNINGS
    )
endif()

