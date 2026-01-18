cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)
include(${WITNESS_SOURCE_DIR}/cmake/LIEFConfig.cmake)

add_library(w1import STATIC
    import_insertion.cpp
)

if(APPLE)
    target_sources(w1import PRIVATE
        platform/macos/macos_import_inserter.cpp
        backend/macos/macho_processor.cpp
    )
elseif(WIN32)
    target_sources(w1import PRIVATE
        platform/windows/windows_import_inserter.cpp
    )
else()
    target_sources(w1import PRIVATE
        platform/linux/linux_import_inserter.cpp
    )
endif()

target_include_directories(w1import
    PUBLIC $<BUILD_INTERFACE:${WITNESS_SOURCE_DIR}/src>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(w1import PRIVATE redlog::redlog)

apply_common_compile_options(w1import)
apply_windows_definitions(w1import)
set_standard_output_dirs(w1import)
configure_target_with_lief(w1import)

set_target_properties(w1import PROPERTIES POSITION_INDEPENDENT_CODE ON)
