# p01s0n - preload injection library for dynamic patching
# this library gets injected into target processes and applies patches at runtime

w1_dep_lua()
w1_dep_redlog()

if(WITNESS_SCRIPT)
    # build as shared library for injection
    w1_add_shared_library(p01s0n
        p01s0n.cpp
        p01s0n.hpp
    )
    add_library(w1::p01s0n ALIAS p01s0n)

    # link p1ll as static library
    target_link_libraries(p01s0n PRIVATE
        p1ll_script
        redlog::redlog
    )

    # remove lib prefix and set platform-specific properties like tracers
    set_target_properties(p01s0n PROPERTIES 
        PREFIX ""  # no lib prefix
    )

    if(APPLE)
        set_target_properties(p01s0n PROPERTIES MACOSX_RPATH TRUE)
    endif()

    # export symbols for dynamic loading
    if(WIN32)
        target_compile_definitions(p01s0n PRIVATE
            P01S0N_EXPORTS
        )
    endif()

    # install target
    install(TARGETS p01s0n
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin
        COMPONENT ${W1_INSTALL_COMPONENT}
    )
    
    message(STATUS "p01s0n dynamic injection library configured")
    
else()
    message(STATUS "p01s0n library skipped - lua scripting not enabled")
endif()
