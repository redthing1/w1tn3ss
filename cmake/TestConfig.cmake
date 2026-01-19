# shared helpers for test targets
include_guard()

if(NOT COMMAND w1_target_defaults)
    include("${CMAKE_CURRENT_LIST_DIR}/W1Init.cmake")
endif()

function(w1_set_test_output_dirs target output_subdir)
    if(NOT output_subdir)
        return()
    endif()

    set_target_properties(${target} PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${output_subdir}
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${output_subdir}
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${output_subdir}
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
    cmake_parse_arguments(W1 "${options}" "${one_value_args}" "${multi_value_args}" ${ARGN})

    if(NOT W1_SOURCES)
        message(FATAL_ERROR "w1_add_doctest_suite requires SOURCES")
    endif()

    add_executable(${target} ${W1_SOURCES})
    if(W1_INCLUDE_DIRS)
        target_include_directories(${target} PRIVATE ${W1_INCLUDE_DIRS})
    endif()
    if(W1_LIBS)
        target_link_libraries(${target} PRIVATE ${W1_LIBS})
    endif()

    w1_target_defaults(${target})

    if(W1_OUTPUT_SUBDIR)
        w1_set_test_output_dirs(${target} ${W1_OUTPUT_SUBDIR})
        add_test(
            NAME ${target}
            COMMAND ${target}
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/${W1_OUTPUT_SUBDIR}
        )
    else()
        add_test(NAME ${target} COMMAND ${target})
    endif()
endfunction()

function(w1_add_harness_test target)
    set(options)
    set(one_value_args OUTPUT_SUBDIR)
    set(multi_value_args SOURCES LIBS INCLUDE_DIRS ARGS)
    cmake_parse_arguments(W1 "${options}" "${one_value_args}" "${multi_value_args}" ${ARGN})

    if(NOT W1_SOURCES)
        message(FATAL_ERROR "w1_add_harness_test requires SOURCES")
    endif()

    add_executable(${target} ${W1_SOURCES})
    if(W1_INCLUDE_DIRS)
        target_include_directories(${target} PRIVATE ${W1_INCLUDE_DIRS})
    endif()
    if(W1_LIBS)
        target_link_libraries(${target} PRIVATE ${W1_LIBS})
    endif()

    w1_target_defaults(${target})

    if(W1_OUTPUT_SUBDIR)
        w1_set_test_output_dirs(${target} ${W1_OUTPUT_SUBDIR})
        set(_w1_working_dir ${CMAKE_BINARY_DIR}/${W1_OUTPUT_SUBDIR})
    else()
        set(_w1_working_dir ${CMAKE_CURRENT_BINARY_DIR})
    endif()

    if(W1_ARGS)
        add_test(
            NAME ${target}
            COMMAND ${target} ${W1_ARGS}
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
