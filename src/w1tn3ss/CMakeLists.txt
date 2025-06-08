set(LIBRARY_NAME w1tn3ss)

# Create library sources list
set(SOURCES
    util/log.cpp
    w1tn3ss.cpp
)

set(HEADERS
    util/log.hpp
    w1tn3ss.hpp
)

# create library target
if(WITNESS_SHARED)
    add_library(${LIBRARY_NAME} SHARED ${SOURCES})
    target_compile_definitions(${LIBRARY_NAME} PRIVATE W1TN3SS_EXPORTS)
else()
    add_library(${LIBRARY_NAME} STATIC ${SOURCES})
endif()

# set target properties including flat output directory
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
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link libraries
target_link_libraries(${LIBRARY_NAME}
    PUBLIC
        QBDI
        common
)

# Compiler flags
target_compile_features(${LIBRARY_NAME} PUBLIC cxx_std_17)

if(WIN32 AND WITNESS_SHARED)
    target_compile_definitions(${LIBRARY_NAME} INTERFACE W1TN3SS_IMPORTS)
endif()

# Install rules
install(TARGETS ${LIBRARY_NAME}
    EXPORT w1tn3ssTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    PUBLIC_HEADER DESTINATION include/w1tn3ss
)