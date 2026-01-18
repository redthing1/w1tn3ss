cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TestConfig.cmake)

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
    gdb_run_policy_test.cpp
    gdb_register_info_test.cpp
    gdb_stepper_test.cpp
    module_source_test.cpp
    replay_context_test.cpp
    ${WITNESS_SOURCE_DIR}/src/w1replay/asmr_block_decoder.cpp
    ${WITNESS_SOURCE_DIR}/src/w1replay/module_source.cpp
    ${WITNESS_SOURCE_DIR}/src/w1replay/gdb/adapter.cpp
    ${WITNESS_SOURCE_DIR}/src/w1replay/gdb/adapter_components.cpp
    ${WITNESS_SOURCE_DIR}/src/w1replay/gdb/layout.cpp
    ${WITNESS_SOURCE_DIR}/src/w1replay/gdb/target_xml.cpp
    ${WITNESS_SOURCE_DIR}/src/w1replay/gdb/memory_merge.cpp
    ${WITNESS_SOURCE_DIR}/src/w1replay/gdb/memory_map.cpp
    ${WITNESS_SOURCE_DIR}/src/w1replay/gdb/value_codec.cpp
    ${WITNESS_SOURCE_DIR}/src/w1replay/gdb/stepper.cpp
)

w1_add_doctest_suite(w1replay_unit_tests
    SOURCES ${W1REPLAY_TEST_SOURCES}
    INCLUDE_DIRS
        ${WITNESS_SOURCE_DIR}/src
        ${WITNESS_SOURCE_DIR}/src/third_party
        ${WITNESS_SOURCE_DIR}/test
    LIBS
        w1rewind_record
        w1rewind_replay
        gdbstub::gdbstub
        Threads::Threads
    OUTPUT_SUBDIR test/w1replay
)

add_test(
    NAME w1replay_trace_e2e
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_LIST_DIR}/e2e/trace_e2e_test.py
        --w1tool ${CMAKE_BINARY_DIR}/bin/w1tool
        --w1replay ${CMAKE_BINARY_DIR}/bin/w1replay
        --samples-dir ${CMAKE_BINARY_DIR}/bin/samples/programs
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
            --w1tool ${CMAKE_BINARY_DIR}/bin/w1tool
            --w1replay ${CMAKE_BINARY_DIR}/bin/w1replay
            --samples-dir ${CMAKE_BINARY_DIR}/bin/samples/programs
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
        --w1tool ${CMAKE_BINARY_DIR}/bin/w1tool
        --w1replay ${CMAKE_BINARY_DIR}/bin/w1replay
        --samples-dir ${CMAKE_BINARY_DIR}/bin/samples/programs
)
set_tests_properties(w1replay_lldb_state_e2e PROPERTIES
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    LABELS \"lldb\"
)
