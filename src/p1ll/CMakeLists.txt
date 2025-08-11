# p1ll binary patching library

if(WITNESS_SCRIPT)
    
    # script engine configuration
    set(PILL_SCRIPT_ENGINE "lua" CACHE STRING "script engine to use (lua or js)")
    set_property(CACHE PILL_SCRIPT_ENGINE PROPERTY STRINGS "lua" "js")

    # include appropriate scripting configuration
    if(PILL_SCRIPT_ENGINE STREQUAL "lua")
        include(${WITNESS_SOURCE_DIR}/cmake/LuaConfig.cmake)
    elseif(PILL_SCRIPT_ENGINE STREQUAL "js")
        # include(${WITNESS_SOURCE_DIR}/cmake/JavaScriptConfig.cmake)  # placeholder
        message(STATUS "javascript engine selected (stub only)")
    else()
        message(FATAL_ERROR "invalid PILL_SCRIPT_ENGINE: ${PILL_SCRIPT_ENGINE} (must be 'lua' or 'js')")
    endif()
    
    # core p1ll library sources
    set(P1LL_SOURCES
        # core implementation
        core/platform.cpp
        core/signature.cpp
        core/context.cpp
        
        # engine implementation
        engine/pattern_matcher.cpp
        engine/memory_scanner.cpp
        engine/auto_cure.cpp
        
        # utility implementation
        utils/hex_utils.cpp
        utils/hex_pattern.cpp
        utils/file_utils.cpp
        utils/pretty_hexdump.cpp
        
        # scripting abstraction
        scripting/script_engine_factory.cpp
    )
    
    # add engine-specific sources
    if(PILL_SCRIPT_ENGINE STREQUAL "lua")
        list(APPEND P1LL_SOURCES
            scripting/lua/lua_engine.cpp
        )
    elseif(PILL_SCRIPT_ENGINE STREQUAL "js")
        list(APPEND P1LL_SOURCES
            scripting/js/js_engine.cpp
        )
    endif()
    
    # create static library
    add_library(p1ll STATIC ${P1LL_SOURCES})
    
    # configure engine-specific integration
    if(PILL_SCRIPT_ENGINE STREQUAL "lua")
        configure_target_with_lua(p1ll)
        message(STATUS "p1ll library configured with lua scripting support")
    elseif(PILL_SCRIPT_ENGINE STREQUAL "js")
        # placeholder for javascript configuration when implemented
        target_compile_definitions(p1ll PUBLIC PILL_SCRIPT_ENGINE_JS=1)
        message(STATUS "p1ll library configured with javascript scripting support (stub)")
    endif()
    
    # link dependencies
    target_link_libraries(p1ll PRIVATE redlog::redlog)
    
    # include directories
    target_include_directories(p1ll 
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..
    )
    
    # set output directory for static library
    set_target_properties(p1ll PROPERTIES 
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        POSITION_INDEPENDENT_CODE ON
    )
    
else()
    message(STATUS "p1ll library skipped: scripting not enabled")
endif()