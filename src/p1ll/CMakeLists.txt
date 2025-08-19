# p1ll binary patching library

# core library sources
set(P1LL_CORE_SOURCES
    core/platform.cpp
    core/signature.cpp
    core/context.cpp
    engine/pattern_matcher.cpp
    engine/memory_scanner.cpp
    engine/auto_cure.cpp
    utils/hex_utils.cpp
    utils/hex_pattern.cpp
    utils/file_utils.cpp
    utils/pretty_hexdump.cpp
)

# p1ll_core static library (always available)
add_library(p1ll_core STATIC ${P1LL_CORE_SOURCES})
target_link_libraries(p1ll_core PUBLIC redlog::redlog)
target_include_directories(p1ll_core 
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..
)
set_target_properties(p1ll_core PROPERTIES 
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    POSITION_INDEPENDENT_CODE ON
)

# p1ll_script static library (optional)
if(WITNESS_SCRIPT)
    # scripting sources
    set(P1LL_SCRIPT_SOURCES
        scripting/script_engine_factory.cpp
    )
    
    # add engine-specific sources
    if(WITNESS_SCRIPT_ENGINE STREQUAL "lua")
        list(APPEND P1LL_SCRIPT_SOURCES scripting/lua/lua_engine.cpp)
    elseif(WITNESS_SCRIPT_ENGINE STREQUAL "js")
        list(APPEND P1LL_SCRIPT_SOURCES scripting/js/js_engine.cpp)
    endif()
    
    add_library(p1ll_script STATIC ${P1LL_SCRIPT_SOURCES})
    target_link_libraries(p1ll_script PUBLIC p1ll_core PRIVATE redlog::redlog)
    target_include_directories(p1ll_script 
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..
    )
    target_compile_definitions(p1ll_script PUBLIC P1LL_HAS_SCRIPTING=1)
    
    # configure engine-specific integration
    if(WITNESS_SCRIPT_ENGINE STREQUAL "lua")
        configure_target_with_lua(p1ll_script)
        message(STATUS "p1ll_script configured with lua support")
    elseif(WITNESS_SCRIPT_ENGINE STREQUAL "js")
        configure_target_with_jnjs(p1ll_script)
        target_compile_definitions(p1ll_script PRIVATE
            PILL_SCRIPT_ENGINE_JS=1
            PILL_HAS_JAVASCRIPT_SUPPORT=1
        )
        message(STATUS "p1ll_script configured with javascript support")
    endif()
    
    set_target_properties(p1ll_script PROPERTIES 
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        POSITION_INDEPENDENT_CODE ON
    )
else()
    message(STATUS "p1ll_core available (scripting disabled)")
endif()