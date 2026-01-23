# WindowsSymbolConfig.cmake - Windows-specific symbol conflict resolution
# handles duplicate symbol issues that occur on Windows MSVC but not on Unix platforms

include_guard()

set(_W1_QBDI_LINK_HINTS
    "QBDI"         # QBDI_static, QBDI::QBDI, QBDIPreload
    "w1cov"
    "w1dump"
    "w1rewind"
    "w1xfer"
    "w1script"
    "w1mem"
    "w1trace"
)

set(_W1_LIEF_LINK_HINTS
    "LIEF"         # LIEF::LIEF or LIEF.lib
    "w1::lief"
    "w1_lief"
    "w1import"
)

function(_w1_target_links_hint TARGET_NAME OUT_VAR)
    set(_patterns ${ARGN})
    foreach(_prop IN ITEMS LINK_LIBRARIES INTERFACE_LINK_LIBRARIES)
        get_target_property(_libs ${TARGET_NAME} ${_prop})
        if(NOT _libs OR _libs STREQUAL "${_prop}-NOTFOUND")
            continue()
        endif()
        foreach(_lib IN LISTS _libs)
            foreach(_pattern IN LISTS _patterns)
                if(_lib MATCHES "${_pattern}")
                    set(${OUT_VAR} TRUE PARENT_SCOPE)
                    return()
                endif()
            endforeach()
        endforeach()
    endforeach()
    set(${OUT_VAR} FALSE PARENT_SCOPE)
endfunction()

# configure Windows-specific linker options to handle duplicate symbols
function(configure_windows_symbol_resolution TARGET_NAME)
    if(NOT (WIN32 AND MSVC))
        return()
    endif()

    _w1_target_links_hint(${TARGET_NAME} _w1_has_qbdi ${_W1_QBDI_LINK_HINTS})
    _w1_target_links_hint(${TARGET_NAME} _w1_has_lief ${_W1_LIEF_LINK_HINTS})

    if(_w1_has_qbdi AND _w1_has_lief)
        message(STATUS "applying fmt conflict resolution for ${TARGET_NAME}")
        # allow first definition to win for duplicates between bundled fmt variants
        target_link_options(${TARGET_NAME} PRIVATE /FORCE:MULTIPLE)
    endif()
endfunction()

# apply Windows symbol resolution to all project targets
function(_w1_collect_targets_recursive DIR OUT_VAR)
    set(_targets "")
    get_property(_dir_targets DIRECTORY "${DIR}" PROPERTY BUILDSYSTEM_TARGETS)
    if(_dir_targets)
        list(APPEND _targets ${_dir_targets})
    endif()

    get_property(_subdirs DIRECTORY "${DIR}" PROPERTY SUBDIRECTORIES)
    foreach(_subdir IN LISTS _subdirs)
        _w1_collect_targets_recursive("${_subdir}" _sub_targets)
        if(_sub_targets)
            list(APPEND _targets ${_sub_targets})
        endif()
    endforeach()

    set(${OUT_VAR} "${_targets}" PARENT_SCOPE)
endfunction()

function(apply_windows_symbol_resolution_to_all)
    # get all targets in this build tree (including subdirectories)
    _w1_collect_targets_recursive("${CMAKE_CURRENT_BINARY_DIR}" targets)
    if(targets)
        list(REMOVE_DUPLICATES targets)
    endif()
    
    foreach(target IN LISTS targets)
        # only apply to executable and library targets
        get_target_property(target_type ${target} TYPE)
        if(target_type MATCHES "EXECUTABLE|SHARED_LIBRARY|MODULE_LIBRARY|STATIC_LIBRARY")
            configure_windows_symbol_resolution(${target})
        endif()
    endforeach()
endfunction()
