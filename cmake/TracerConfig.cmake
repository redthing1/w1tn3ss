# tracer library configuration
include_guard()

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)

# create tracer library targets (shared and static)
function(create_tracer_targets tracer_name source_files)
    if(WITNESS_BUILD_SHARED)
        add_library(${tracer_name}_qbdipreload SHARED ${source_files})
        configure_tracer_target(${tracer_name}_qbdipreload ${tracer_name})
    endif()

    if(WITNESS_BUILD_STATIC)
        add_library(${tracer_name}_static STATIC ${source_files})        
        configure_tracer_target(${tracer_name}_static ${tracer_name})
    endif()
endfunction()

# configure individual tracer target
function(configure_tracer_target target_name tracer_name)
    target_include_directories(${target_name} PRIVATE
        ${WITNESS_SOURCE_DIR}/src
        ${WITNESS_SOURCE_DIR}/src/third_party/qbdi/tools/QBDIPreload/include
    )

    target_link_libraries(${target_name} PRIVATE
        w1tn3ss
        QBDI_static
        redlog::redlog
    )
    
    # on linux only, force inclusion of static library symbols for shared library
    if(${target_name} MATCHES "_qbdipreload$" AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_options(${target_name} PRIVATE "LINKER:--whole-archive,$<TARGET_FILE:QBDI_static>,--no-whole-archive")
    endif()
    
    # on windows only, force inclusion of static library symbols for shared library
    if(${target_name} MATCHES "_qbdipreload$" AND CMAKE_SYSTEM_NAME STREQUAL "Windows")
        target_link_options(${target_name} PRIVATE "/WHOLEARCHIVE:$<TARGET_FILE:QBDI_static>")
    endif()
    
    # link qbdipreload for shared library version
    if(${target_name} MATCHES "_qbdipreload$")
        target_link_libraries(${target_name} PRIVATE QBDIPreload)
    endif()

    apply_common_compile_options(${target_name})
    apply_windows_definitions(${target_name})
    set_standard_output_dirs(${target_name})

    # remove lib prefix and set macos rpath
    set_target_properties(${target_name} PROPERTIES PREFIX "")
    if(APPLE)
        set_target_properties(${target_name} PROPERTIES MACOSX_RPATH TRUE)
    elseif(UNIX)
        target_link_libraries(${target_name} PRIVATE dl)
    endif()
endfunction()