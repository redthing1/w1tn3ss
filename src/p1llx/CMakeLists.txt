# p1llx static binary patcher tool

if(WITNESS_SCRIPT)
    # p1llx executable sources
    set(P1LLX_SOURCES
        main.cpp
        commands/cure.cpp
        commands/patch.cpp
        commands/poison.cpp
        commands/sig.cpp
    )

    if(WITNESS_ASMR)
        list(APPEND P1LLX_SOURCES
            commands/asm.cpp
            commands/disasm.cpp
        )
    endif()
    
    # create executable
    w1_add_executable(p1llx ${P1LLX_SOURCES})
    
    # link with p1ll library and dependencies
    target_link_libraries(p1llx 
        PRIVATE 
        p1ll_core
        p1ll_script
        w1base
        w1nj3ct
    )

    if(WITNESS_ASMR)
        target_link_libraries(p1llx PRIVATE w1asmr)
    endif()
    
    install(TARGETS p1llx
        RUNTIME DESTINATION bin
        COMPONENT ${W1_INSTALL_COMPONENT}
    )

    message(STATUS "p1llx static patcher tool configured")
    
else()
    message(STATUS "p1llx tool skipped - lua scripting not enabled")
endif()
