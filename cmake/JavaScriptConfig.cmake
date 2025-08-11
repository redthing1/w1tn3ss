# javascriptconfig.cmake - jnjs configuration module
# provides functions for setting up jnjs javascript engine

# configure target with javascript support
function(configure_target_with_jnjs target)
    if(NOT WITNESS_SCRIPT)
        message(FATAL_ERROR "configure_target_with_jnjs called but WITNESS_SCRIPT=OFF")
        return()
    endif()
    
    if(NOT WITNESS_SCRIPT_ENGINE STREQUAL "js")
        message(FATAL_ERROR "configure_target_with_jnjs called but WITNESS_SCRIPT_ENGINE=${WITNESS_SCRIPT_ENGINE}")
        return()
    endif()
    
    # link against jnjs library (this will include headers and quickjs automatically)
    target_link_libraries(${target} PRIVATE jnjs)
    
    # add general javascript support flag
    target_compile_definitions(${target} PRIVATE WITNESS_SCRIPT_ENABLED=1)
    
    message(STATUS "configured ${target} with javascript support via jnjs")
endfunction()