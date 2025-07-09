# p01s0n - preload injection library for dynamic patching
# this library gets injected into target processes and applies patches at runtime

cmake_minimum_required(VERSION 3.18)

# check if lua scripting is enabled (required for p01s0n)
include(${WITNESS_SOURCE_DIR}/cmake/LuaConfig.cmake)

if(WITNESS_SCRIPT)
    include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)

    # build as shared library for injection
    add_library(p01s0n SHARED
        p01s0n.cpp
        p01s0n.hpp
    )

    # configure lua integration like p1ll
    configure_target_with_lua(p01s0n)

    # link p1ll as static library
    target_link_libraries(p01s0n PRIVATE
        p1ll
        redlog::redlog
    )

    # include directories
    target_include_directories(p01s0n PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${WITNESS_SOURCE_DIR}/src
    )

    # apply common configuration like other w1 libraries
    apply_common_compile_options(p01s0n)
    apply_windows_definitions(p01s0n)
    set_standard_output_dirs(p01s0n)

    # remove lib prefix and set platform-specific properties like tracers
    set_target_properties(p01s0n PROPERTIES 
        PREFIX ""  # no lib prefix
        POSITION_INDEPENDENT_CODE ON
    )

    if(APPLE)
        set_target_properties(p01s0n PROPERTIES MACOSX_RPATH TRUE)
    elseif(UNIX)
        target_link_libraries(p01s0n PRIVATE dl)
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
    )
    
    message(STATUS "p01s0n dynamic injection library configured")
    
else()
    message(STATUS "p01s0n library skipped - lua scripting not enabled")
endif()