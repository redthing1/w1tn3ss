if(WITNESS_SCRIPT)
    message(STATUS "building w1script tracer with lua support")
    w1_dep_lua()

    w1_add_tracer(w1script
        SOURCES
            preload.cpp
            script_tracer.cpp
            runtime/lua_runtime.cpp
            runtime/callback_registry.cpp
            runtime/output_state.cpp
            runtime/script_context.cpp
            bindings/w1_bindings.cpp
            bindings/root.cpp
            bindings/util.cpp
            bindings/inst.cpp
            bindings/mem.cpp
            bindings/reg.cpp
            bindings/module.cpp
            bindings/symbol.cpp
            bindings/output.cpp
            bindings/abi.cpp
        LIBS w1analysis w1formats w1::lua
    )
else()
    message(STATUS "w1script tracer disabled (WITNESS_SCRIPT=OFF)")
endif()
