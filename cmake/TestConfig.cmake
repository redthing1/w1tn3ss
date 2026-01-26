# shared helpers for test targets
include_guard()

if(NOT COMMAND w1_target_defaults)
    include("${CMAKE_CURRENT_LIST_DIR}/W1Init.cmake")
endif()

function(w1_resolve_test_output_dir out_var output_subdir)
    set(output_dir "${WITNESS_OUTPUT_TEST_DIR}")
    if(output_subdir)
        if(IS_ABSOLUTE "${output_subdir}")
            set(output_dir "${output_subdir}")
        else()
            set(output_dir "${WITNESS_OUTPUT_TEST_DIR}/${output_subdir}")
        endif()
    endif()
    set(${out_var} "${output_dir}" PARENT_SCOPE)
endfunction()

function(w1_set_test_output_dirs target output_subdir)
    w1_resolve_test_output_dir(output_dir "${output_subdir}")

    set_target_properties(${target} PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${output_dir}
        RUNTIME_OUTPUT_DIRECTORY ${output_dir}
        ARCHIVE_OUTPUT_DIRECTORY ${output_dir}
    )
endfunction()

function(w1_disable_sanitizers target)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT WIN32)
        target_compile_options(${target} PRIVATE -fno-sanitize=all)
        target_link_options(${target} PRIVATE -fno-sanitize=all)
    endif()
endfunction()

function(w1_add_doctest_suite target)
    set(options)
    set(one_value_args OUTPUT_SUBDIR)
    set(multi_value_args SOURCES LIBS INCLUDE_DIRS)
    cmake_parse_arguments(WITNESS "${options}" "${one_value_args}" "${multi_value_args}" ${ARGN})

    if(NOT WITNESS_SOURCES)
        message(FATAL_ERROR "w1_add_doctest_suite requires SOURCES")
    endif()

    add_executable(${target} ${WITNESS_SOURCES})
    w1_register_target(${target})
    if(WITNESS_INCLUDE_DIRS)
        target_include_directories(${target} PRIVATE ${WITNESS_INCLUDE_DIRS})
    endif()
    if(WITNESS_LIBS)
        target_link_libraries(${target} PRIVATE ${WITNESS_LIBS})
    endif()

    w1_apply_test_defaults(${target})
    w1_set_test_output_dirs(${target} "${WITNESS_OUTPUT_SUBDIR}")

    w1_resolve_test_output_dir(_w1_working_dir "${WITNESS_OUTPUT_SUBDIR}")

    add_test(
        NAME ${target}
        COMMAND ${target}
        WORKING_DIRECTORY ${_w1_working_dir}
    )
endfunction()

function(w1_add_harness_test target)
    set(options)
    set(one_value_args OUTPUT_SUBDIR)
    set(multi_value_args SOURCES LIBS INCLUDE_DIRS ARGS)
    cmake_parse_arguments(WITNESS "${options}" "${one_value_args}" "${multi_value_args}" ${ARGN})

    if(NOT WITNESS_SOURCES)
        message(FATAL_ERROR "w1_add_harness_test requires SOURCES")
    endif()

    add_executable(${target} ${WITNESS_SOURCES})
    w1_register_target(${target})
    if(WITNESS_INCLUDE_DIRS)
        target_include_directories(${target} PRIVATE ${WITNESS_INCLUDE_DIRS})
    endif()
    if(WITNESS_LIBS)
        target_link_libraries(${target} PRIVATE ${WITNESS_LIBS})
    endif()

    w1_apply_test_defaults(${target})
    w1_set_test_output_dirs(${target} "${WITNESS_OUTPUT_SUBDIR}")

    w1_resolve_test_output_dir(_w1_working_dir "${WITNESS_OUTPUT_SUBDIR}")

    if(WITNESS_ARGS)
        add_test(
            NAME ${target}
            COMMAND ${target} ${WITNESS_ARGS}
            WORKING_DIRECTORY ${_w1_working_dir}
        )
    else()
        add_test(
            NAME ${target}
            COMMAND ${target}
            WORKING_DIRECTORY ${_w1_working_dir}
        )
    endif()
endfunction()
