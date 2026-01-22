include(${W1_SOURCE_DIR}/cmake/TestConfig.cmake)

w1_add_harness_test(test_standalone_tracers
    SOURCES test_standalone_tracers.cpp
    INCLUDE_DIRS ${W1_SOURCE_DIR}/src
    LIBS w1cov_static w1xfer_static
    OUTPUT_SUBDIR harness
    ARGS all
)

if(WITNESS_SCRIPT)
    target_link_libraries(test_standalone_tracers PRIVATE w1script_static)
endif()

if(WIN32 AND MSVC)
    include(${W1_SOURCE_DIR}/cmake/WindowsSymbolConfig.cmake)
    configure_windows_symbol_resolution(test_standalone_tracers)
endif()

w1_add_harness_test(test_gadget_executor
    SOURCES test_gadget_executor.cpp
    INCLUDE_DIRS ${W1_SOURCE_DIR}/src
    LIBS w1gadget
    OUTPUT_SUBDIR harness
)

w1_add_harness_test(test_rewind_format
    SOURCES test_rewind_format.cpp
    INCLUDE_DIRS ${W1_SOURCE_DIR}/src
    LIBS w1rewind_record w1rewind_replay
    OUTPUT_SUBDIR harness
)

w1_add_harness_test(test_monitor_demo
    SOURCES test_monitor_demo.cpp
    INCLUDE_DIRS
        ${W1_SOURCE_DIR}/src
        ${W1_SOURCE_DIR}/test/common
    LIBS w1monitor ${CMAKE_DL_LIBS}
    OUTPUT_SUBDIR harness
)

w1_add_harness_test(test_w1cov_multithread_demo
    SOURCES test_w1cov_multithread_demo.cpp
    INCLUDE_DIRS
        ${W1_SOURCE_DIR}/src
        ${W1_SOURCE_DIR}/test/common
    LIBS w1cov_static ${CMAKE_DL_LIBS}
    OUTPUT_SUBDIR harness
)

if(TARGET w1cov_demo_lib)
    add_dependencies(test_w1cov_multithread_demo w1cov_demo_lib)
endif()

w1_add_harness_test(test_w1cov_components
    SOURCES test_w1cov_components.cpp
    INCLUDE_DIRS ${W1_SOURCE_DIR}/src
    LIBS w1cov_static
    OUTPUT_SUBDIR harness
)

w1_add_harness_test(test_w1cov_single_thread
    SOURCES
        test_w1cov_single_thread.cpp
        w1cov_test_targets.cpp
    INCLUDE_DIRS ${W1_SOURCE_DIR}/src
    LIBS w1cov_static
    OUTPUT_SUBDIR harness
)

set_tests_properties(test_gadget_executor PROPERTIES
    LABELS "unit;gadget;executor"
)
