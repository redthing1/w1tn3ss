cmake_minimum_required(VERSION 3.16)

include(${CMAKE_SOURCE_DIR}/cmake/TracerConfig.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/LuaConfig.cmake)

if(WITNESS_SCRIPT)
    message(STATUS "building w1script tracer with lua support")
    
    setup_lua_environment()
    
    create_tracer_targets(w1script
        "preload.cpp;script_tracer.cpp;script_bindings.cpp;bindings/core_types.cpp;bindings/register_access.cpp;bindings/vm_control.cpp;bindings/memory_analysis.cpp;bindings/utilities.cpp;bindings/callback_system.cpp"
    )
    
    configure_target_with_lua(w1script_qbdipreload)
    configure_target_with_lua(w1script_static)
    
else()
    message(STATUS "w1script tracer disabled (WITNESS_SCRIPT=OFF)")
    
    create_tracer_targets(w1script "preload.cpp;script_tracer.cpp")
endif()