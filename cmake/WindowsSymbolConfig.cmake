# WindowsSymbolConfig.cmake - Windows-specific symbol conflict resolution
# handles duplicate symbol issues that occur on Windows MSVC but not on Unix platforms

include_guard()

# configure Windows-specific linker options to handle duplicate symbols
function(configure_windows_symbol_resolution target)
    if(WIN32 AND MSVC)
        # check if target links both QBDI and LIEF (potential conflict sources)
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
        
        # also check common witness wrapper targets that imply QBDI/LIEF usage
        if(target_libs)
            foreach(lib IN LISTS target_libs)
                if(lib MATCHES "w1import")
                    set(has_lief TRUE)
                endif()
                if(lib MATCHES "w1runtime|w1instrument|w1analysis|w1dump|w1gadget|w1cov|w1mem|w1trace|w1inst|w1xfer|w1script|w1rewind")
                    set(has_qbdi TRUE)
                endif()
            endforeach()
        endif()
        
        # debug output to see what we found
        message(DEBUG "${target}: has_qbdi=${has_qbdi}, has_lief=${has_lief}, libs=${target_libs}")
        
        if(has_qbdi AND has_lief)
            message(STATUS "applying fmt conflict resolution for ${target}")
            # only handle specific fmt library conflicts between LIEF and QBDI
            target_link_options(${target} PRIVATE
                /FORCE:MULTIPLE    # allow first definition to win for duplicates
            )
        endif()
    endif()
endfunction()

# apply Windows symbol resolution to all project targets
function(apply_windows_symbol_resolution_to_all)
    # get all targets in the current directory and subdirectories
    get_property(targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
    
    foreach(target IN LISTS targets)
        # only apply to executable and library targets
        get_target_property(target_type ${target} TYPE)
        if(target_type MATCHES "EXECUTABLE|SHARED_LIBRARY|MODULE_LIBRARY|STATIC_LIBRARY")
            configure_windows_symbol_resolution(${target})
        endif()
    endforeach()
endfunction()
