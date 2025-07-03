# p1ll binary patching library

# check if lua scripting is enabled
include(${CMAKE_SOURCE_DIR}/cmake/LuaConfig.cmake)

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
        utils/file_utils.cpp
        
        # scripting implementation
        scripting/lua_bindings.cpp
        scripting/lua_api.cpp
        
        # main library interface
        p1ll.cpp
    )
    
    # create shared library for injection
    add_library(p1ll SHARED ${P1LL_SOURCES})
    
    # configure lua integration
    configure_target_with_lua(p1ll)
    
    # link dependencies
    target_link_libraries(p1ll PRIVATE redlog::redlog)
    
    # include directories
    target_include_directories(p1ll 
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..
    )
    
    # set output name without lib prefix on macos for injection and output to lib directory
    set_target_properties(p1ll PROPERTIES 
        PREFIX ""
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    )
    
    message(STATUS "p1ll library configured with lua scripting support")
    
else()
    message(STATUS "p1ll library skipped - lua scripting not enabled")
endif()