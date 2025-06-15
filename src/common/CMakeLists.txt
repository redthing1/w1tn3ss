set(LIBRARY_NAME common)

# Header-only library with external dependencies
add_library(${LIBRARY_NAME} INTERFACE)

# Include directories for external headers
target_include_directories(${LIBRARY_NAME}
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include/common>
)

# This is a header-only library, so we only need to specify interface requirements
target_compile_features(${LIBRARY_NAME} INTERFACE cxx_std_20)

# Install rules for headers
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/ext/
    DESTINATION include/common/ext
    FILES_MATCHING PATTERN "*.hpp" PATTERN "*.h"
)

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/platform_utils.hpp
    DESTINATION include/common
)

install(TARGETS ${LIBRARY_NAME}
    EXPORT w1tn3ssTargets
)