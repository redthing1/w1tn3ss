include(${W1_SOURCE_DIR}/cmake/TestConfig.cmake)

w1_add_harness_test(test_w1xfer
    SOURCES test_w1xfer.cpp
    INCLUDE_DIRS
        ${W1_SOURCE_DIR}/src
        ${W1_SOURCE_DIR}/src/tracers/w1xfer
    LIBS w1xfer_static
    OUTPUT_SUBDIR harness
)

if(WITNESS_SCRIPT AND TARGET w1script_static)
    w1_add_harness_test(test_w1script
        SOURCES test_w1script.cpp
        INCLUDE_DIRS
            ${W1_SOURCE_DIR}/src
            ${W1_SOURCE_DIR}/src/tracers/w1script
        LIBS w1script_static
        OUTPUT_SUBDIR harness
    )
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
        ${W1_SOURCE_DIR}/src/tracers/w1cov
        ${W1_SOURCE_DIR}/test/common
    LIBS w1cov_static ${CMAKE_DL_LIBS}
    OUTPUT_SUBDIR harness
)

if(TARGET w1cov_demo_lib)
    add_dependencies(test_w1cov_multithread_demo w1cov_demo_lib)
endif()

w1_add_harness_test(test_w1cov_components
    SOURCES test_w1cov_components.cpp
    INCLUDE_DIRS
        ${W1_SOURCE_DIR}/src
        ${W1_SOURCE_DIR}/src/tracers/w1cov
    LIBS w1cov_static
    OUTPUT_SUBDIR harness
)

w1_add_harness_test(test_w1cov_single_thread
    SOURCES
        test_w1cov_single_thread.cpp
        w1cov_test_targets.cpp
    INCLUDE_DIRS
        ${W1_SOURCE_DIR}/src
        ${W1_SOURCE_DIR}/src/tracers/w1cov
    LIBS w1cov_static
    OUTPUT_SUBDIR harness
)

w1_add_harness_test(test_w1cov_module_filtering
    SOURCES test_w1cov_module_filtering.cpp
    INCLUDE_DIRS
        ${W1_SOURCE_DIR}/src
        ${W1_SOURCE_DIR}/src/tracers/w1cov
        ${W1_SOURCE_DIR}/test/common
    LIBS w1cov_static ${CMAKE_DL_LIBS}
    OUTPUT_SUBDIR harness
)

if(TARGET w1cov_demo_lib)
    add_dependencies(test_w1cov_module_filtering w1cov_demo_lib)
endif()

set_tests_properties(test_gadget_executor PROPERTIES
    LABELS "harness;unit;gadget;executor"
)

set_tests_properties(test_w1xfer PROPERTIES
    LABELS "harness;tracers;w1xfer"
)

if(TARGET test_w1script)
    set_tests_properties(test_w1script PROPERTIES
        LABELS "harness;tracers;w1script"
    )
endif()

set_tests_properties(test_rewind_format PROPERTIES
    LABELS "harness;rewind"
)

set_tests_properties(test_monitor_demo PROPERTIES
    LABELS "harness;monitor"
)

set_tests_properties(test_w1cov_components PROPERTIES
    LABELS "harness;w1cov;components"
)

set_tests_properties(test_w1cov_single_thread PROPERTIES
    LABELS "harness;w1cov;single_thread"
)

set_tests_properties(test_w1cov_multithread_demo PROPERTIES
    LABELS "harness;w1cov;multithread"
)

set_tests_properties(test_w1cov_module_filtering PROPERTIES
    LABELS "harness;w1cov;module_filtering"
)
