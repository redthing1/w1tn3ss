cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)

add_library(common INTERFACE)

target_include_directories(common INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/w1common>
)

target_compile_features(common INTERFACE cxx_std_17)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/ext/
    DESTINATION include/w1common/ext
    FILES_MATCHING PATTERN "*.hpp" PATTERN "*.h"
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/cli/
    DESTINATION include/w1common/cli
    FILES_MATCHING PATTERN "*.hpp" PATTERN "*.h"
)

file(GLOB COMMON_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/*.hpp)
install(FILES ${COMMON_HEADERS}
    DESTINATION include/w1common
)

install(TARGETS common EXPORT w1tn3ssTargets)
