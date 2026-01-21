cmake_minimum_required(VERSION 3.16)

include(${W1_SOURCE_DIR}/cmake/TestConfig.cmake)

find_package(Threads REQUIRED)
find_package(Python3 COMPONENTS Interpreter REQUIRED)

set(W1REPLAY_TEST_SOURCES
    test_main.cpp
    gdb_adapter_test.cpp
    gdb_layout_test.cpp
    gdb_target_xml_test.cpp
    gdb_memory_map_test.cpp
    gdb_memory_read_test.cpp
    gdb_pc_only_test.cpp
    gdb_host_process_info_test.cpp
    gdb_run_policy_test.cpp
    gdb_register_info_test.cpp
    gdb_stepper_test.cpp
    gdb_value_codec_test.cpp
    gdb_loaded_libraries_test.cpp
    module_image_test.cpp
    module_address_index_test.cpp
    module_path_resolver_test.cpp
    replay_context_test.cpp
    ${W1_SOURCE_DIR}/src/w1replay/modules/address_index.cpp
    ${W1_SOURCE_DIR}/src/w1replay/modules/module_image.cpp
    ${W1_SOURCE_DIR}/src/w1replay/modules/module_image_lief.cpp
    ${W1_SOURCE_DIR}/src/w1replay/modules/asmr_block_decoder.cpp
    ${W1_SOURCE_DIR}/src/w1replay/modules/lief_module_provider.cpp
    ${W1_SOURCE_DIR}/src/w1replay/modules/path_resolver.cpp
    ${W1_SOURCE_DIR}/src/w1replay/trace_loader/trace_loader.cpp
    ${W1_SOURCE_DIR}/src/w1replay/gdb/adapter.cpp
    ${W1_SOURCE_DIR}/src/w1replay/gdb/loaded_libraries_provider.cpp
    ${W1_SOURCE_DIR}/src/w1replay/gdb/triple_utils.cpp
    ${W1_SOURCE_DIR}/src/w1replay/gdb/components/regs_component.cpp
    ${W1_SOURCE_DIR}/src/w1replay/gdb/components/mem_component.cpp
    ${W1_SOURCE_DIR}/src/w1replay/gdb/components/run_component.cpp
    ${W1_SOURCE_DIR}/src/w1replay/gdb/components/breakpoints_component.cpp
    ${W1_SOURCE_DIR}/src/w1replay/gdb/components/threads_component.cpp
    ${W1_SOURCE_DIR}/src/w1replay/gdb/components/host_info_component.cpp
    ${W1_SOURCE_DIR}/src/w1replay/gdb/components/memory_layout_component.cpp
    ${W1_SOURCE_DIR}/src/w1replay/gdb/components/libraries_component.cpp
    ${W1_SOURCE_DIR}/src/w1replay/gdb/components/loaded_libraries_component.cpp
    ${W1_SOURCE_DIR}/src/w1replay/gdb/components/process_info_component.cpp
    ${W1_SOURCE_DIR}/src/w1replay/gdb/components/offsets_component.cpp
    ${W1_SOURCE_DIR}/src/w1replay/gdb/components/register_info_component.cpp
    ${W1_SOURCE_DIR}/src/w1replay/gdb/lldb/darwin_loaded_libraries.cpp
    ${W1_SOURCE_DIR}/src/w1replay/gdb/layout.cpp
    ${W1_SOURCE_DIR}/src/w1replay/gdb/target_xml.cpp
    ${W1_SOURCE_DIR}/src/w1replay/gdb/memory_map.cpp
    ${W1_SOURCE_DIR}/src/w1replay/memory/memory_view.cpp
    ${W1_SOURCE_DIR}/src/w1replay/gdb/value_codec.cpp
    ${W1_SOURCE_DIR}/src/w1replay/gdb/stepper.cpp
)

w1_add_doctest_suite(w1replay_unit_tests
    SOURCES ${W1REPLAY_TEST_SOURCES}
    INCLUDE_DIRS
        ${W1_SOURCE_DIR}/src
        ${W1_SOURCE_DIR}/src/third_party
        ${W1_SOURCE_DIR}/test
    LIBS
        w1rewind_record
        w1rewind_replay
        gdbstub::gdbstub
        Threads::Threads
    OUTPUT_SUBDIR w1replay
)

add_test(
    NAME w1replay_trace_e2e
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_LIST_DIR}/e2e/trace_e2e_test.py
        --w1tool ${W1_OUTPUT_BIN_DIR}/w1tool${CMAKE_EXECUTABLE_SUFFIX}
        --w1replay ${W1_OUTPUT_BIN_DIR}/w1replay${CMAKE_EXECUTABLE_SUFFIX}
        --samples-dir ${W1_OUTPUT_SAMPLE_DIR}/programs
)
set_tests_properties(w1replay_trace_e2e PROPERTIES
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    LABELS \"trace\"
)

if(WITNESS_LIEF)
    add_test(
        NAME w1replay_lldb_flow_e2e
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_LIST_DIR}/e2e/lldb_flow_e2e_test.py
            --w1tool ${W1_OUTPUT_BIN_DIR}/w1tool${CMAKE_EXECUTABLE_SUFFIX}
            --w1replay ${W1_OUTPUT_BIN_DIR}/w1replay${CMAKE_EXECUTABLE_SUFFIX}
            --samples-dir ${W1_OUTPUT_SAMPLE_DIR}/programs
    )
    set_tests_properties(w1replay_lldb_flow_e2e PROPERTIES
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        LABELS \"lldb\"
    )
endif()

add_test(
    NAME w1replay_lldb_state_e2e
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_LIST_DIR}/e2e/lldb_state_e2e_test.py
        --w1tool ${W1_OUTPUT_BIN_DIR}/w1tool${CMAKE_EXECUTABLE_SUFFIX}
        --w1replay ${W1_OUTPUT_BIN_DIR}/w1replay${CMAKE_EXECUTABLE_SUFFIX}
        --samples-dir ${W1_OUTPUT_SAMPLE_DIR}/programs
)
set_tests_properties(w1replay_lldb_state_e2e PROPERTIES
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    LABELS \"lldb\"
)
