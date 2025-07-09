cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)

add_library(w1tn3ss STATIC
    util/env_config.cpp
    util/env_enumerator.cpp
    util/module_scanner.cpp
    util/module_range_index.cpp
    util/memory_range_index.cpp
    util/signal_handler.cpp
    util/safe_memory.cpp
    util/register_capture.cpp
    util/stack_capture.cpp
    util/value_formatter.cpp
    util/jsonl_writer.cpp
    # new calling convention system
    abi/calling_convention_factory.cpp
    abi/calling_convention_detector.cpp
    # existing abi components
    abi/api_knowledge_db.cpp
    abi/argument_extractor.cpp
    abi/api_analyzer.cpp
    abi/api_listener.cpp
    # hooking system
    hooking/hook_manager.cpp
)

# Add platform-specific calling convention implementations
# Use QBDI_ARCH which is properly set based on target architecture
if(QBDI_ARCH STREQUAL "X86_64")
    target_sources(w1tn3ss PRIVATE
        abi/conventions/x86_64/system_v.cpp
        abi/conventions/x86_64/microsoft.cpp
    )
elseif(QBDI_ARCH STREQUAL "X86")
    target_sources(w1tn3ss PRIVATE
        abi/conventions/x86/cdecl.cpp
        # abi/conventions/x86/stdcall.cpp
        # abi/conventions/x86/fastcall.cpp
        # abi/conventions/x86/thiscall.cpp
    )
elseif(QBDI_ARCH STREQUAL "AARCH64")
    target_sources(w1tn3ss PRIVATE
        abi/conventions/arm/aarch64_aapcs.cpp
    )
elseif(QBDI_ARCH STREQUAL "ARM")
    # TODO: add ARM32 conventions when implemented
    # target_sources(w1tn3ss PRIVATE
    #     abi/conventions/arm/arm32_aapcs.cpp
    # )
endif()

# Always compile the unified symbol resolver (it has conditional logic)
target_sources(w1tn3ss PRIVATE
    lief/symbol_resolver.cpp
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
    
    # Add Windows-specific system resolver
    if(WIN32)
        target_sources(w1tn3ss PRIVATE
            lief/windows_system_resolver.cpp
        )
    endif()
endif()

target_include_directories(w1tn3ss PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${WITNESS_SOURCE_DIR}/src
)

target_link_libraries(w1tn3ss PUBLIC
    QBDI_static
    redlog::redlog
)

apply_common_compile_options(w1tn3ss)
set_standard_output_dirs(w1tn3ss)
apply_platform_linking(w1tn3ss)
configure_target_with_lief(w1tn3ss)
