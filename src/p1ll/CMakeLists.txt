# p1ll binary patching library

w1_dep_redlog()

# core library sources
set(P1LL_CORE_SOURCES
    engine/address_space.cpp
    engine/apply.cpp
    engine/pattern.cpp
    engine/pattern_matcher.cpp
    engine/plan_builder.cpp
    engine/scanner.cpp
    engine/session.cpp
    engine/platform/platform.cpp
    engine/platform/process_memory_macos.cpp
    engine/platform/process_memory_linux.cpp
    engine/platform/process_memory_windows.cpp
    utils/hex_utils.cpp
    utils/hex_pattern.cpp
    utils/file_utils.cpp
    utils/pretty_hexdump.cpp
)

# p1ll_core static library (always available)
w1_add_static_library(p1ll_core ${P1LL_CORE_SOURCES})
add_library(p1ll::core ALIAS p1ll_core)
target_link_libraries(p1ll_core PUBLIC redlog::redlog)
target_include_directories(p1ll_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/..
)

# p1ll_script static library (optional)
if(WITNESS_SCRIPT)
    w1_dep_lua()
    if(WITNESS_SCRIPT_ENGINE STREQUAL "js")
        w1_dep_jnjs()
    endif()
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
    
    w1_add_static_library(p1ll_script ${P1LL_SCRIPT_SOURCES})
    add_library(p1ll::script ALIAS p1ll_script)
    target_link_libraries(p1ll_script PUBLIC p1ll_core PRIVATE redlog::redlog)
    target_include_directories(p1ll_script
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/..
    )
    target_compile_definitions(p1ll_script PUBLIC P1LL_HAS_SCRIPTING=1)
    
    # configure engine-specific integration
    if(WITNESS_SCRIPT_ENGINE STREQUAL "lua")
        target_link_libraries(p1ll_script PUBLIC w1::lua)
        message(STATUS "p1ll_script configured with lua support")
    elseif(WITNESS_SCRIPT_ENGINE STREQUAL "js")
        target_link_libraries(p1ll_script PUBLIC w1::jnjs)
        target_compile_definitions(p1ll_script PRIVATE
            PILL_SCRIPT_ENGINE_JS=1
            PILL_HAS_JAVASCRIPT_SUPPORT=1
        )
        message(STATUS "p1ll_script configured with javascript support")
    endif()
else()
    message(STATUS "p1ll_core available (scripting disabled)")
endif()

# p1ll_c api wrapper (optional)
option(P1LL_BUILD_CAPI "Build C API wrapper for p1ll" OFF)

if(P1LL_BUILD_CAPI)
    add_subdirectory(capi)
    message(STATUS "p1ll c api enabled")
endif()

# p1ll_heur static library (optional)
if(WITNESS_ASMR)
    w1_dep_asmr()
    set(P1LL_HEUR_SOURCES
        heur/code_signature.cpp
    )

    w1_add_static_library(p1ll_heur ${P1LL_HEUR_SOURCES})
    add_library(p1ll::heur ALIAS p1ll_heur)
    target_link_libraries(p1ll_heur PUBLIC p1ll_core w1asmr)
    target_include_directories(p1ll_heur
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/..
    )
endif()
