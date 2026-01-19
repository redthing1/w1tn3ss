# target helper functions for w1tn3ss
include_guard()

if(NOT DEFINED W1_SOURCE_DIR)
    set(W1_SOURCE_DIR "${PROJECT_SOURCE_DIR}")
endif()

if(NOT COMMAND w1_target_defaults)
    include("${CMAKE_CURRENT_LIST_DIR}/W1Options.cmake")
endif()

function(w1_apply_component_defaults TARGET_NAME)
    w1_target_defaults(${TARGET_NAME})

    target_include_directories(${TARGET_NAME}
        PUBLIC $<BUILD_INTERFACE:${W1_SOURCE_DIR}/src>
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
    )

    set_target_properties(${TARGET_NAME} PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY ${W1_OUTPUT_LIB_DIR}
        LIBRARY_OUTPUT_DIRECTORY ${W1_OUTPUT_LIB_DIR}
        RUNTIME_OUTPUT_DIRECTORY ${W1_OUTPUT_LIB_DIR}
        POSITION_INDEPENDENT_CODE ON
    )
endfunction()

function(w1_apply_executable_defaults TARGET_NAME)
    w1_target_defaults(${TARGET_NAME})

    target_include_directories(${TARGET_NAME}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
    )

    set_target_properties(${TARGET_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${W1_OUTPUT_BIN_DIR}
    )
endfunction()

function(w1_add_static_library TARGET_NAME)
    add_library(${TARGET_NAME} STATIC ${ARGN})
    w1_apply_component_defaults(${TARGET_NAME})
endfunction()

function(w1_add_shared_library TARGET_NAME)
    add_library(${TARGET_NAME} SHARED ${ARGN})
    w1_apply_component_defaults(${TARGET_NAME})
endfunction()

function(w1_add_executable TARGET_NAME)
    add_executable(${TARGET_NAME} ${ARGN})
    w1_apply_executable_defaults(${TARGET_NAME})
endfunction()

function(w1_apply_test_defaults TARGET_NAME)
    w1_apply_executable_defaults(${TARGET_NAME})
    set_target_properties(${TARGET_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${W1_OUTPUT_TEST_DIR}
    )
endfunction()

function(w1_add_test_executable TARGET_NAME)
    add_executable(${TARGET_NAME} ${ARGN})
    w1_apply_test_defaults(${TARGET_NAME})
endfunction()
