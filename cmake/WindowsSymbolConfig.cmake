# WindowsSymbolConfig.cmake - Windows-specific symbol conflict resolution
# Handles duplicate symbol issues that occur on Windows MSVC but not on Unix platforms

include_guard()

# Configure Windows-specific linker options to handle duplicate symbols
function(configure_windows_symbol_resolution target)
    # Check if target links both QBDI and LIEF (potential conflict sources)
    get_target_property(target_libs ${target} LINK_LIBRARIES)
    set(has_qbdi FALSE)
    set(has_lief FALSE)
    
    if(target_libs)
        foreach(lib IN LISTS target_libs)
            if(lib MATCHES "QBDI")
                set(has_qbdi TRUE)
            endif()
            if(lib MATCHES "LIEF")
                set(has_lief TRUE)
            endif()
        endforeach()
    endif()
    
    if(has_qbdi AND has_lief)
        message(STATUS "Applying Windows duplicate symbol resolution for ${target}")
        
        # Use MSVC linker options to gracefully handle duplicate symbols
        target_link_options(${target} PRIVATE
            /IGNORE:4006  # Ignore duplicate symbol warnings (LNK2005)
            /IGNORE:4221  # Ignore empty object file warnings
        )
        
        # Ensure consistent runtime library to avoid additional conflicts
        set_target_properties(${target} PROPERTIES
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
        )
    endif()
endfunction()

# Apply Windows symbol resolution to all project targets
function(apply_windows_symbol_resolution_to_all)
    # Get all targets in the current directory and subdirectories
    get_property(targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
    
    foreach(target IN LISTS targets)
        # Only apply to executable and library targets
        get_target_property(target_type ${target} TYPE)
        if(target_type MATCHES "EXECUTABLE|SHARED_LIBRARY|MODULE_LIBRARY|STATIC_LIBRARY")
            configure_windows_symbol_resolution(${target})
        endif()
    endforeach()
endfunction()