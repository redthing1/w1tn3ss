# sample programs for tracer demos and instrumentation targets

include(${W1_SOURCE_DIR}/cmake/SampleConfig.cmake)

set(samples_output_dir ${W1_OUTPUT_SAMPLE_DIR}/programs)

add_subdirectory(instraware)

# core sample programs
w1_add_sample_program(multi_threaded_target
    SOURCES multi_threaded_target.c
    OUTPUT_DIR ${samples_output_dir}
)

w1_add_sample_program(control_flow_1
    SOURCES control_flow_1.cpp
    OUTPUT_DIR ${samples_output_dir}
)

w1_add_sample_program(runtime_injection_target
    SOURCES runtime_injection_target.c
    OUTPUT_DIR ${samples_output_dir}
)

w1_add_sample_program(simple_demo
    SOURCES simple_demo.c
    OUTPUT_DIR ${samples_output_dir}
)

# rewind tracer demos
w1_add_sample_program(rewind_demo_basic
    SOURCES rewind_demo_basic.c
    OUTPUT_DIR ${samples_output_dir}
)

w1_add_sample_program(rewind_demo_calls
    SOURCES rewind_demo_calls.c
    OUTPUT_DIR ${samples_output_dir}
)

w1_add_sample_program(rewind_demo_memops
    SOURCES rewind_demo_memops.c
    OUTPUT_DIR ${samples_output_dir}
)

w1_add_sample_program(rewind_demo_io
    SOURCES rewind_demo_io.c
    OUTPUT_DIR ${samples_output_dir}
)

w1_add_sample_program(rewind_demo_algorithms
    SOURCES rewind_demo_algorithms.c
    OUTPUT_DIR ${samples_output_dir}
)

# thread test demo programs
w1_add_sample_program(threadtest_demo
    SOURCES threadtest_demo.c
    OUTPUT_DIR ${samples_output_dir}
)

w1_add_sample_program(threadtest_evasive_demo
    SOURCES threadtest_evasive_demo.cpp
    OUTPUT_DIR ${samples_output_dir}
)

# hook test target program for signature-based hooking
w1_add_sample_program(hook_test_target
    SOURCES hook_test_target.c
    OUTPUT_DIR ${samples_output_dir}
)

# linux-specific target programs
if(UNIX AND NOT APPLE)
    w1_add_sample_program(linux_target
        SOURCES linux_target.c
        OUTPUT_DIR ${samples_output_dir}
    )

    w1_add_sample_program(linux_daemon
        SOURCES linux_daemon.c
        OUTPUT_DIR ${samples_output_dir}
    )
endif()

# p1ll sample program (only build when lua scripting is enabled)
if(WITNESS_SCRIPT)
    w1_add_sample_program(p1ll_test_target
        SOURCES p1ll_test_target.c
        OUTPUT_DIR ${samples_output_dir}
    )
endif()

# platform-specific linking
if(WIN32)
    # no additional libraries needed for Windows
elseif(UNIX)
    target_link_libraries(multi_threaded_target PRIVATE pthread)
    target_link_libraries(runtime_injection_target PRIVATE pthread)
    target_link_libraries(threadtest_demo PRIVATE pthread)
    target_link_libraries(threadtest_evasive_demo PRIVATE pthread)
endif()

# enable sanitizers for sample programs in debug builds
set(sample_targets
    multi_threaded_target
    control_flow_1
    runtime_injection_target
    simple_demo
    rewind_demo_basic
    rewind_demo_calls
    rewind_demo_memops
    rewind_demo_io
    rewind_demo_algorithms
    threadtest_demo
    threadtest_evasive_demo
    hook_test_target
)

list(APPEND sample_targets
    instraware_qbdi_rai
    instraware_qbdi_stack
    instraware_qbdi_smc
    instraware_qbdi_fault
)

if(WITNESS_SCRIPT)
    list(APPEND sample_targets p1ll_test_target)
endif()

if(UNIX AND NOT APPLE)
    list(APPEND sample_targets linux_target linux_daemon)
endif()

w1_apply_debug_sanitizers_to_targets(${sample_targets})

# install targets
install(TARGETS ${sample_targets}
    RUNTIME DESTINATION bin/samples/programs
    COMPONENT ${W1_INSTALL_COMPONENT}
)
