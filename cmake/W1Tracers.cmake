# helper functions for tracer libraries
include_guard()

if(NOT DEFINED W1_SOURCE_DIR)
    set(W1_SOURCE_DIR "${PROJECT_SOURCE_DIR}")
endif()

if(NOT COMMAND w1_target_defaults)
    include("${CMAKE_CURRENT_LIST_DIR}/W1Init.cmake")
endif()

function(w1_configure_tracer_target TARGET_NAME)
    target_include_directories(${TARGET_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${W1_SOURCE_DIR}/src/third_party/qbdi/tools/QBDIPreload/include
    )

    target_link_libraries(${TARGET_NAME} PUBLIC
        w1instrument
        QBDI::QBDI
    )

    if(${TARGET_NAME} MATCHES "_qbdipreload$")
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            target_link_options(${TARGET_NAME} PRIVATE "LINKER:--whole-archive,$<TARGET_FILE:QBDI_static>,--no-whole-archive")
        elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
            target_link_options(${TARGET_NAME} PRIVATE "/WHOLEARCHIVE:$<TARGET_FILE:QBDI_static>")
        endif()

        if(TARGET QBDIPreload)
            target_link_libraries(${TARGET_NAME} PRIVATE QBDIPreload)
        endif()
    endif()

    w1_target_defaults(${TARGET_NAME})

    set_target_properties(${TARGET_NAME} PROPERTIES PREFIX "")
    set_target_properties(${TARGET_NAME} PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY ${W1_OUTPUT_LIB_DIR}
        LIBRARY_OUTPUT_DIRECTORY ${W1_OUTPUT_LIB_DIR}
        RUNTIME_OUTPUT_DIRECTORY ${W1_OUTPUT_LIB_DIR}
    )
    if(APPLE)
        set_target_properties(${TARGET_NAME} PROPERTIES MACOSX_RPATH TRUE)
    endif()
endfunction()

function(w1_add_tracer TRACER_NAME)
    set(options)
    set(one_value_args)
    set(multi_value_args SOURCES LIBS)
    cmake_parse_arguments(W1 "${options}" "${one_value_args}" "${multi_value_args}" ${ARGN})

    if(NOT W1_SOURCES)
        message(FATAL_ERROR "w1_add_tracer requires SOURCES")
    endif()

    if(WITNESS_BUILD_SHARED)
        add_library(${TRACER_NAME}_qbdipreload SHARED ${W1_SOURCES})
        w1_register_target(${TRACER_NAME}_qbdipreload)
        w1_configure_tracer_target(${TRACER_NAME}_qbdipreload)
        if(W1_LIBS)
            target_link_libraries(${TRACER_NAME}_qbdipreload PUBLIC ${W1_LIBS})
        endif()

        install(TARGETS ${TRACER_NAME}_qbdipreload
            RUNTIME DESTINATION lib COMPONENT ${W1_INSTALL_COMPONENT}
            LIBRARY DESTINATION lib COMPONENT ${W1_INSTALL_COMPONENT}
            ARCHIVE DESTINATION lib COMPONENT ${W1_INSTALL_COMPONENT}
        )
    endif()

    if(WITNESS_BUILD_STATIC)
        add_library(${TRACER_NAME}_static STATIC ${W1_SOURCES})
        w1_register_target(${TRACER_NAME}_static)
        w1_configure_tracer_target(${TRACER_NAME}_static)
        if(W1_LIBS)
            target_link_libraries(${TRACER_NAME}_static PUBLIC ${W1_LIBS})
        endif()
    endif()
endfunction()
