cmake_minimum_required(VERSION 3.16)

include(${CMAKE_SOURCE_DIR}/cmake/TracerConfig.cmake)

option(WITNESS_SCRIPT "Enable w1script tracer with Lua support" OFF)

if(WITNESS_SCRIPT)
    message(STATUS "Building w1script tracer with Lua support")
    
    # Find required packages
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LUAJIT REQUIRED luajit)
    
    # Include sol2 submodule
    set(SOL2_DIR "${CMAKE_SOURCE_DIR}/src/third_party/sol2")
    if(NOT EXISTS "${SOL2_DIR}/include/sol/sol.hpp")
        message(FATAL_ERROR "sol2 submodule not found at ${SOL2_DIR}. Please run: git submodule update --init --recursive")
    endif()
    
    # Create w1script tracer with Lua support
    create_tracer_targets(w1script
        "preload.cpp;script_tracer.cpp;script_bindings.cpp;bindings/core_types.cpp;bindings/register_access.cpp;bindings/vm_control.cpp;bindings/memory_analysis.cpp;bindings/utilities.cpp;bindings/callback_system.cpp"
    )
    
    # Add Lua-specific configuration
    if(TARGET w1script_qbdipreload)
        target_include_directories(w1script_qbdipreload PRIVATE
            ${SOL2_DIR}/include
            ${LUAJIT_INCLUDE_DIRS}
        )
        
        target_link_directories(w1script_qbdipreload PRIVATE
            ${LUAJIT_LIBRARY_DIRS}
        )
        
        target_link_libraries(w1script_qbdipreload PRIVATE
            ${LUAJIT_LIBRARIES}
        )
        
        target_compile_definitions(w1script_qbdipreload PRIVATE
            WITNESS_SCRIPT_ENABLED=1
        )
    endif()
    
    if(TARGET w1script_static)
        target_include_directories(w1script_static PRIVATE
            ${SOL2_DIR}/include
            ${LUAJIT_INCLUDE_DIRS}
        )
        
        target_link_directories(w1script_static PRIVATE
            ${LUAJIT_LIBRARY_DIRS}
        )
        
        target_link_libraries(w1script_static PRIVATE
            ${LUAJIT_LIBRARIES}
        )
        
        target_compile_definitions(w1script_static PRIVATE
            WITNESS_SCRIPT_ENABLED=1
        )
    endif()
    
else()
    message(STATUS "w1script tracer disabled (WITNESS_SCRIPT=OFF)")
    
    # Create minimal stub tracer without Lua support  
    create_tracer_targets(w1script "preload.cpp;script_tracer.cpp")
endif()