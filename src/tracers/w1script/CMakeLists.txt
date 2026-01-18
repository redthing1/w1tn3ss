cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TracerConfig.cmake)
include(${WITNESS_SOURCE_DIR}/cmake/LuaConfig.cmake)

if(WITNESS_SCRIPT)
    message(STATUS "building w1script tracer with lua support")

    create_tracer_targets(w1script
        "preload.cpp;script_tracer.cpp;runtime/lua_runtime.cpp;runtime/callback_registry.cpp;runtime/output_state.cpp;runtime/script_context.cpp;bindings/w1_bindings.cpp;bindings/root.cpp;bindings/util.cpp;bindings/inst.cpp;bindings/mem.cpp;bindings/reg.cpp;bindings/module.cpp;bindings/symbol.cpp;bindings/output.cpp;bindings/abi.cpp"
    )

    configure_target_with_lua(w1script_qbdipreload)
    configure_target_with_lua(w1script_static)

    foreach(target w1script_qbdipreload w1script_static)
        if(TARGET ${target})
            target_link_libraries(${target} PUBLIC w1analysis w1formats)
        endif()
    endforeach()
else()
    message(STATUS "w1script tracer disabled (WITNESS_SCRIPT=OFF)")
endif()
