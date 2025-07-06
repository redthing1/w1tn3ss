cmake_minimum_required(VERSION 3.16)

include(${CMAKE_SOURCE_DIR}/cmake/TracerConfig.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/LuaConfig.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/LIEFConfig.cmake)

if(WITNESS_SCRIPT)
    message(STATUS "building w1script tracer with lua support")
    
    create_tracer_targets(w1script
        "preload.cpp;script_tracer.cpp;script_bindings.cpp;bindings/core_types.cpp;bindings/register_access.cpp;bindings/vm_control.cpp;bindings/memory_analysis.cpp;bindings/module_analysis.cpp;bindings/utilities.cpp;bindings/callback_system.cpp;bindings/api_analysis.cpp"
    )
    
    configure_target_with_lua(w1script_qbdipreload)
    configure_target_with_lua(w1script_static)
    
    # Apply LIEF configuration for symbol resolution
    if(WITNESS_BUILD_SHARED)
        configure_target_with_lief(w1script_qbdipreload)
    endif()
    
    if(WITNESS_BUILD_STATIC)
        configure_target_with_lief(w1script_static)
    endif()
    
else()
    message(STATUS "w1script tracer disabled (WITNESS_SCRIPT=OFF)")
endif()