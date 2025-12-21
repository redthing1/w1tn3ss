# sample programs for tracer demos and instrumentation targets

set(samples_output_dir ${CMAKE_BINARY_DIR}/samples/programs)

add_subdirectory(instraware)

# multi-threaded target program
add_executable(multi_threaded_target multi_threaded_target.c)
apply_common_compile_options(multi_threaded_target)
apply_windows_definitions(multi_threaded_target)
set_target_properties(multi_threaded_target PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${samples_output_dir}
)

# control flow crackme program
add_executable(control_flow_1 control_flow_1.cpp)
apply_common_compile_options(control_flow_1)
apply_windows_definitions(control_flow_1)
set_target_properties(control_flow_1 PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${samples_output_dir}
)

# runtime injection target program
add_executable(runtime_injection_target runtime_injection_target.c)
apply_common_compile_options(runtime_injection_target)
apply_windows_definitions(runtime_injection_target)
set_target_properties(runtime_injection_target PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${samples_output_dir}
)

# simple demo program for script testing
add_executable(simple_demo simple_demo.c)
apply_common_compile_options(simple_demo)
apply_windows_definitions(simple_demo)
set_target_properties(simple_demo PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${samples_output_dir}
)

# thread test demo program
add_executable(threadtest_demo threadtest_demo.c)
apply_common_compile_options(threadtest_demo)
apply_windows_definitions(threadtest_demo)
set_target_properties(threadtest_demo PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${samples_output_dir}
)

# thread evasive thread scenario demo program
add_executable(threadtest_evasive_demo threadtest_evasive_demo.cpp)
apply_common_compile_options(threadtest_evasive_demo)
apply_windows_definitions(threadtest_evasive_demo)
set_target_properties(threadtest_evasive_demo PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${samples_output_dir}
)

# hook test target program for testing signature-based hooking
add_executable(hook_test_target hook_test_target.c)
apply_common_compile_options(hook_test_target)
apply_windows_definitions(hook_test_target)
set_target_properties(hook_test_target PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${samples_output_dir}
)

# linux-specific target programs
if(UNIX AND NOT APPLE)
    # linux injection target with linux-specific features
    add_executable(linux_target linux_target.c)
    apply_common_compile_options(linux_target)
    apply_windows_definitions(linux_target)
    set_target_properties(linux_target PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${samples_output_dir}
    )

    # linux daemon target for testing background process injection
    add_executable(linux_daemon linux_daemon.c)
    apply_common_compile_options(linux_daemon)
    apply_windows_definitions(linux_daemon)
    set_target_properties(linux_daemon PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${samples_output_dir}
    )
endif()

# platform-specific linking
if(WIN32)
    # no additional libraries needed for Windows
elseif(UNIX)
    # link pthread for unix systems
    target_link_libraries(multi_threaded_target PRIVATE pthread)
    target_link_libraries(runtime_injection_target PRIVATE pthread)
    target_link_libraries(threadtest_demo PRIVATE pthread)
    target_link_libraries(threadtest_evasive_demo PRIVATE pthread)
endif()

# p1ll sample programs (only build when lua scripting is enabled)
if(WITNESS_SCRIPT)
    # p1ll binary patching target
    add_executable(p1ll_test_target p1ll_test_target.c)
    apply_common_compile_options(p1ll_test_target)
    apply_windows_definitions(p1ll_test_target)
    set_target_properties(p1ll_test_target PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${samples_output_dir}
    )
endif()

# enable sanitizers for sample programs in debug builds
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT WIN32)
    target_compile_options(multi_threaded_target PRIVATE ${SANITIZER_FLAGS})
    target_link_options(multi_threaded_target PRIVATE ${SANITIZER_FLAGS})

    target_compile_options(control_flow_1 PRIVATE ${SANITIZER_FLAGS})
    target_link_options(control_flow_1 PRIVATE ${SANITIZER_FLAGS})

    target_compile_options(runtime_injection_target PRIVATE ${SANITIZER_FLAGS})
    target_link_options(runtime_injection_target PRIVATE ${SANITIZER_FLAGS})

    # p1ll sample targets (when scripting is enabled)
    if(WITNESS_SCRIPT)
        target_compile_options(p1ll_test_target PRIVATE ${SANITIZER_FLAGS})
        target_link_options(p1ll_test_target PRIVATE ${SANITIZER_FLAGS})
    endif()

    # linux-specific targets
    if(UNIX AND NOT APPLE)
        target_compile_options(linux_target PRIVATE ${SANITIZER_FLAGS})
        target_link_options(linux_target PRIVATE ${SANITIZER_FLAGS})

        target_compile_options(linux_daemon PRIVATE ${SANITIZER_FLAGS})
        target_link_options(linux_daemon PRIVATE ${SANITIZER_FLAGS})
    endif()
endif()

# install targets
set(sample_targets
    multi_threaded_target
    control_flow_1
    runtime_injection_target
    simple_demo
    threadtest_demo
    threadtest_evasive_demo
    hook_test_target
    instraware_qbdi_rai
    instraware_qbdi_stack
    instraware_qbdi_smc
    instraware_qbdi_fault
)

# add p1ll targets to install list when scripting is enabled
if(WITNESS_SCRIPT)
    list(APPEND sample_targets p1ll_test_target)
endif()

# add linux-specific targets to install list
if(UNIX AND NOT APPLE)
    list(APPEND sample_targets linux_target linux_daemon)
endif()

install(TARGETS ${sample_targets}
    RUNTIME DESTINATION samples/programs
)
