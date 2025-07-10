cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TracerConfig.cmake)
include(${WITNESS_SOURCE_DIR}/cmake/LuaConfig.cmake)
include(${WITNESS_SOURCE_DIR}/cmake/LIEFConfig.cmake)

if(WITNESS_SCRIPT)
    message(STATUS "building w1script tracer with lua support")
    
    create_tracer_targets(w1script
        "preload.cpp;script_tracer.cpp;script_bindings.cpp;script_loader.cpp;callback_manager.cpp;api_analysis_processor.cpp;bindings/core_types.cpp;bindings/register_access.cpp;bindings/vm_control.cpp;bindings/memory_access.cpp;bindings/memory_analysis.cpp;bindings/module_analysis.cpp;bindings/utilities.cpp;bindings/callback_system.cpp;bindings/api_analysis.cpp;bindings/hooking.cpp;bindings/signature_scanning.cpp;bindings/calling_convention.cpp;bindings/symbol_resolution.cpp;bindings/output.cpp"
    )
    
    configure_target_with_lua(w1script_qbdipreload)
    configure_target_with_lua(w1script_static)
    
    # Apply LIEF configuration for symbol resolution
    if(WITNESS_BUILD_SHARED)
        configure_target_with_lief(w1script_qbdipreload)
        target_link_libraries(w1script_qbdipreload PRIVATE p1ll)
    endif()
    
    if(WITNESS_BUILD_STATIC)
        configure_target_with_lief(w1script_static)
        target_link_libraries(w1script_static PRIVATE p1ll)
    endif()
    
else()
    message(STATUS "w1script tracer disabled (WITNESS_SCRIPT=OFF)")
endif()