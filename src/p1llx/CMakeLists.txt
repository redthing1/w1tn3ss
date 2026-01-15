# p1llx static binary patcher tool

# check if lua scripting is enabled (required for p1ll)
include(${WITNESS_SOURCE_DIR}/cmake/LuaConfig.cmake)

if(WITNESS_SCRIPT)
    # p1llx executable sources
    set(P1LLX_SOURCES
        main.cpp
        commands/cure.cpp
        commands/patch.cpp
        commands/poison.cpp
        commands/sig.cpp
    )

    if(P1LL_BUILD_ASMR)
        list(APPEND P1LLX_SOURCES
            commands/asm.cpp
            commands/disasm.cpp
        )
    endif()
    
    # create executable
    add_executable(p1llx ${P1LLX_SOURCES})
    
    # configure lua integration
    configure_target_with_lua(p1llx)
    
    # link with p1ll library and dependencies
    target_link_libraries(p1llx 
        PRIVATE 
        p1ll_core
        p1ll_script
        w1nj3ct
        redlog::redlog
    )

    if(P1LL_BUILD_ASMR)
        target_link_libraries(p1llx PRIVATE p1ll_asmr)
    endif()
    
    # include directories
    target_include_directories(p1llx 
        PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${CMAKE_CURRENT_SOURCE_DIR}/../common
    )
    
    # set output directory to root like w1tool
    set_target_properties(p1llx PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    
    message(STATUS "p1llx static patcher tool configured")
    
else()
    message(STATUS "p1llx tool skipped - lua scripting not enabled")
endif()
