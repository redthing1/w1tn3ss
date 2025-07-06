cmake_minimum_required(VERSION 3.16)

include(${CMAKE_SOURCE_DIR}/cmake/CommonConfig.cmake)

add_library(w1tn3ss STATIC
    util/env_config.cpp
    util/module_scanner.cpp
    util/module_range_index.cpp
    util/memory_range_index.cpp
    util/signal_handler.cpp
    util/safe_memory.cpp
    abi/calling_convention.cpp
)

# Add LIEF components when enabled
if(WITNESS_LIEF)
    target_sources(w1tn3ss PRIVATE
        lief/lief_symbol_resolver.cpp
    )
    
    # Add macOS-specific dyld resolver
    if(APPLE)
        target_sources(w1tn3ss PRIVATE
            lief/macos_dyld_resolver.cpp
        )
    endif()
endif()

target_include_directories(w1tn3ss PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(w1tn3ss PUBLIC
    QBDI_static
    redlog::redlog
)

apply_common_compile_options(w1tn3ss)
set_standard_output_dirs(w1tn3ss)
apply_platform_linking(w1tn3ss)
configure_target_with_lief(w1tn3ss)
