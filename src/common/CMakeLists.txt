cmake_minimum_required(VERSION 3.16)

include(${CMAKE_SOURCE_DIR}/cmake/CommonConfig.cmake)

add_library(common INTERFACE)

target_include_directories(common INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/common>
)

target_compile_features(common INTERFACE cxx_std_17)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/ext/
    DESTINATION include/common/ext
    FILES_MATCHING PATTERN "*.hpp" PATTERN "*.h"
)

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/platform_utils.hpp
    DESTINATION include/common
)

install(TARGETS common EXPORT w1tn3ssTargets)