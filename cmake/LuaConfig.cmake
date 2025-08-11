# luaconfig.cmake - lua/sol2 configuration module
# provides functions for setting up lua and sol2 dependencies

# global scripting configuration
option(WITNESS_SCRIPT "enable scripting support" OFF)
set(WITNESS_SCRIPT_ENGINE "lua" CACHE STRING "script engine to use (lua or js)")
set_property(CACHE WITNESS_SCRIPT_ENGINE PROPERTY STRINGS "lua" "js")

include(${WITNESS_SOURCE_DIR}/cmake/LuaJITBuild.cmake)

# validate sol2 submodule availability
function(validate_sol2_submodule)
    set(SOL2_DIR "${WITNESS_SOURCE_DIR}/src/third_party/sol2")
    if(NOT EXISTS "${SOL2_DIR}/include/sol/sol.hpp")
        message(FATAL_ERROR "sol2 submodule not found at ${SOL2_DIR}. run: git submodule update --init --recursive")
    endif()
    
    set(SOL2_DIR ${SOL2_DIR} PARENT_SCOPE)
endfunction()

# configure a target with lua/sol2 dependencies
function(configure_target_with_lua target_name)
    if(NOT WITNESS_SCRIPT)
        return()
    endif()
    
    if(TARGET ${target_name})
        target_include_directories(${target_name} PUBLIC ${SOL2_DIR}/include)
        target_link_libraries(${target_name} PRIVATE ${LUAJIT_LIBRARIES} luajit::header)
        target_compile_definitions(${target_name} PUBLIC WITNESS_SCRIPT_ENABLED=1)
    endif()
endfunction()

# setup lua environment (luajit + sol2)
function(setup_lua_environment)
    if(NOT WITNESS_SCRIPT)
        return()
    endif()
    
    validate_sol2_submodule()
    build_luajit_from_source()
    
    # export variables for parent scope
    set(SOL2_DIR ${SOL2_DIR} PARENT_SCOPE)
    set(LUAJIT_INCLUDE_DIRS ${LUAJIT_INCLUDE_DIRS} PARENT_SCOPE)
    set(LUAJIT_LIBRARIES ${LUAJIT_LIBRARIES} PARENT_SCOPE)
    set(LUAJIT_STATIC_TARGET ${LUAJIT_STATIC_TARGET} PARENT_SCOPE)
endfunction()