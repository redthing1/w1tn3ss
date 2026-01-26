# shared helpers for sample programs
include_guard()

if(NOT COMMAND w1_target_defaults)
    include("${CMAKE_CURRENT_LIST_DIR}/W1Init.cmake")
endif()

function(w1_add_sample_program target)
    set(options)
    set(one_value_args OUTPUT_DIR)
    set(multi_value_args SOURCES)
    cmake_parse_arguments(WITNESS "${options}" "${one_value_args}" "${multi_value_args}" ${ARGN})

    if(NOT WITNESS_SOURCES)
        message(FATAL_ERROR "w1_add_sample_program requires SOURCES")
    endif()

    add_executable(${target} ${WITNESS_SOURCES})
    w1_register_target(${target})
    w1_target_defaults(${target})

    set(sample_output_dir "${WITNESS_OUTPUT_SAMPLE_DIR}")
    if(WITNESS_OUTPUT_DIR)
        set(sample_output_dir "${WITNESS_OUTPUT_DIR}")
    endif()

    set_target_properties(${target} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${sample_output_dir}
    )
endfunction()

function(w1_apply_debug_sanitizers target)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT WIN32)
        target_compile_options(${target} PRIVATE ${SANITIZER_FLAGS})
        target_link_options(${target} PRIVATE ${SANITIZER_FLAGS})
    endif()
endfunction()

function(w1_apply_debug_sanitizers_to_targets)
    foreach(target IN LISTS ARGN)
        w1_apply_debug_sanitizers(${target})
    endforeach()
endfunction()
