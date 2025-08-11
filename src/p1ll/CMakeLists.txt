# p1ll binary patching library

if(WITNESS_SCRIPT)
    
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
    if(WITNESS_SCRIPT_ENGINE STREQUAL "lua")
        list(APPEND P1LL_SOURCES
            scripting/lua/lua_engine.cpp
        )
    elseif(WITNESS_SCRIPT_ENGINE STREQUAL "js")
        list(APPEND P1LL_SOURCES
            scripting/js/js_engine.cpp
        )
    endif()
    
    # create static library
    add_library(p1ll STATIC ${P1LL_SOURCES})
    
    # configure engine-specific integration
    if(WITNESS_SCRIPT_ENGINE STREQUAL "lua")
        configure_target_with_lua(p1ll)
        message(STATUS "p1ll library configured with lua scripting support")
    elseif(WITNESS_SCRIPT_ENGINE STREQUAL "js")
        configure_target_with_jnjs(p1ll)
        # add p1ll-specific javascript defines
        target_compile_definitions(p1ll PRIVATE
            PILL_SCRIPT_ENGINE_JS=1
            PILL_HAS_JAVASCRIPT_SUPPORT=1
        )
        message(STATUS "p1ll library configured with javascript scripting support")
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