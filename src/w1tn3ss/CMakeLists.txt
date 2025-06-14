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

# Create main w1tn3ss library target
if(WITNESS_SHARED)
    add_library(${LIBRARY_NAME} SHARED ${SOURCES})
    target_compile_definitions(${LIBRARY_NAME} PRIVATE W1TN3SS_EXPORTS)
else()
    add_library(${LIBRARY_NAME} STATIC ${SOURCES})
endif()

# Set target properties including flat output directory
set_target_properties(${LIBRARY_NAME} PROPERTIES
    PUBLIC_HEADER "${HEADERS}"
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    PREFIX ""
    OUTPUT_NAME "w1tn3ss"
)

# Include directories
target_include_directories(${LIBRARY_NAME}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link libraries
target_link_libraries(${LIBRARY_NAME}
    PUBLIC
        QBDI
        common
        redlog::redlog
)

# Compiler flags
target_compile_features(${LIBRARY_NAME} PUBLIC cxx_std_17)

# sanitizers disabled - cause crashes with QBDI injection
# if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT WIN32)
#     target_compile_options(${LIBRARY_NAME} PRIVATE ${SANITIZER_FLAGS})
#     target_link_options(${LIBRARY_NAME} PRIVATE ${SANITIZER_FLAGS})
# endif()

if(WIN32 AND WITNESS_SHARED)
    target_compile_definitions(${LIBRARY_NAME} INTERFACE W1TN3SS_IMPORTS)
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
        QBDI
        QBDIPreload
        redlog::redlog
)

target_compile_features(w1cov_qbdipreload PRIVATE cxx_std_17)

# injection libraries do not use sanitizers

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

# Standalone QBDI coverage library
set(W1COV_STANDALONE_SOURCES
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

# injection libraries do not use sanitizers

# Install rules
install(TARGETS ${LIBRARY_NAME} w1cov_qbdipreload w1cov w1cov_runtime w1cov_sampling
    EXPORT w1tn3ssTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    PUBLIC_HEADER DESTINATION include/w1tn3ss
)