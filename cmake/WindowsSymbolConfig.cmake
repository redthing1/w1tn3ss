# WindowsSymbolConfig.cmake - Windows-specific symbol conflict resolution
# handles duplicate symbol issues that occur on Windows MSVC but not on Unix platforms

include_guard()

set(_WITNESS_QBDI_LINK_HINTS
    "QBDI"         # QBDI_static, QBDI::QBDI, QBDIPreload
    "w1cov"
    "w1dump"
    "w1rewind"
    "w1xfer"
    "w1script"
    "w1mem"
    "w1trace"
)

set(_WITNESS_LIEF_LINK_HINTS
    "LIEF"         # LIEF::LIEF or LIEF.lib
    "w1::lief"
    "w1_lief"
    "w1import"
)

function(_w1_normalize_link_item ITEM OUT_VAR)
    set(_value "${ITEM}")
    if(_value MATCHES "^\\$<LINK_ONLY:(.+)>$")
        set(_value "${CMAKE_MATCH_1}")
    elseif(_value MATCHES "^\\$<TARGET_NAME_IF_EXISTS:([^>]+)>$")
        set(_value "${CMAKE_MATCH_1}")
    elseif(_value MATCHES "^\\$<TARGET_OBJECTS:([^>]+)>$")
        set(_value "${CMAKE_MATCH_1}")
    endif()
    set(${OUT_VAR} "${_value}" PARENT_SCOPE)
endfunction()

function(_w1_target_has_link_hint_impl TARGET_NAME OUT_VAR)
    set(options)
    set(one_value_args)
    set(multi_value_args PATTERNS VISITED)
    cmake_parse_arguments(WITNESS "${options}" "${one_value_args}" "${multi_value_args}" ${ARGN})

    if(TARGET_NAME IN_LIST WITNESS_VISITED)
        set(${OUT_VAR} FALSE PARENT_SCOPE)
        return()
    endif()
    list(APPEND WITNESS_VISITED ${TARGET_NAME})

    foreach(_prop IN ITEMS LINK_LIBRARIES INTERFACE_LINK_LIBRARIES)
        get_target_property(_libs ${TARGET_NAME} ${_prop})
        if(NOT _libs OR _libs STREQUAL "${_prop}-NOTFOUND")
            continue()
        endif()
        foreach(_lib IN LISTS _libs)
            _w1_normalize_link_item("${_lib}" _norm)
            foreach(_pattern IN LISTS WITNESS_PATTERNS)
                if(_norm MATCHES "${_pattern}")
                    set(${OUT_VAR} TRUE PARENT_SCOPE)
                    return()
                endif()
            endforeach()

            if(TARGET ${_norm})
                get_target_property(_aliased ${_norm} ALIASED_TARGET)
                if(_aliased)
                    set(_norm ${_aliased})
                endif()
                _w1_target_has_link_hint_impl(${_norm} _child
                    PATTERNS ${WITNESS_PATTERNS}
                    VISITED ${WITNESS_VISITED}
                )
                if(_child)
                    set(${OUT_VAR} TRUE PARENT_SCOPE)
                    return()
                endif()
            endif()
        endforeach()
    endforeach()

    set(${OUT_VAR} FALSE PARENT_SCOPE)
endfunction()

function(_w1_target_has_link_hint TARGET_NAME OUT_VAR)
    _w1_target_has_link_hint_impl(${TARGET_NAME} _hint_found PATTERNS ${ARGN})
    set(${OUT_VAR} ${_hint_found} PARENT_SCOPE)
endfunction()

# configure Windows-specific linker options to handle duplicate symbols
function(configure_windows_symbol_resolution TARGET_NAME)
    if(NOT (WIN32 AND MSVC))
        return()
    endif()

    _w1_target_has_link_hint(${TARGET_NAME} _w1_has_qbdi ${_WITNESS_QBDI_LINK_HINTS})
    _w1_target_has_link_hint(${TARGET_NAME} _w1_has_lief ${_WITNESS_LIEF_LINK_HINTS})

    if(_w1_has_qbdi AND _w1_has_lief)
        message(STATUS "applying fmt conflict resolution for ${TARGET_NAME}")
        # allow first definition to win for duplicates between bundled fmt variants
        target_link_options(${TARGET_NAME} PRIVATE /FORCE:MULTIPLE)
    endif()
endfunction()

function(w1_register_target_for_symbol_resolution TARGET_NAME)
    set_property(GLOBAL APPEND PROPERTY WITNESS_WINDOWS_SYMBOL_TARGETS ${TARGET_NAME})
endfunction()

function(apply_windows_symbol_resolution_to_all)
    get_property(targets GLOBAL PROPERTY WITNESS_WINDOWS_SYMBOL_TARGETS)
    if(NOT targets)
        return()
    endif()
    list(REMOVE_DUPLICATES targets)

    foreach(target IN LISTS targets)
        # only apply to executable and library targets
        get_target_property(target_type ${target} TYPE)
        if(target_type MATCHES "EXECUTABLE|SHARED_LIBRARY|MODULE_LIBRARY|STATIC_LIBRARY")
            configure_windows_symbol_resolution(${target})
        endif()
    endforeach()
endfunction()
