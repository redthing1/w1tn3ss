cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TestConfig.cmake)

set(W1TN3SS_TEST_SOURCES
    test_main.cpp
    memory_reader_test.cpp
    module_registry_test.cpp
    event_router_test.cpp
    instrumentation_policy_test.cpp
    trace_session_smoke_test.cpp
    interval_test.cpp
    jsonl_writer_test.cpp
    symbol_lookup_test.cpp
    abi_dispatcher_test.cpp
    rewind_trace_io_test.cpp
    rewind_recorder_recording_test.cpp
    rewind_recorder_block_recording_test.cpp
    rewind_trace_index_test.cpp
    rewind_trace_cursor_test.cpp
    rewind_replay_cursor_test.cpp
    rewind_replay_instruction_cursor_test.cpp
    rewind_replay_checkpoint_test.cpp
    rewind_replay_session_test.cpp
    rewind_replay_state_applier_test.cpp
    rewind_replay_state_test.cpp
)

w1_add_doctest_suite(w1tn3ss_unit_tests
    SOURCES ${W1TN3SS_TEST_SOURCES}
    INCLUDE_DIRS
        ${WITNESS_SOURCE_DIR}/src
        ${WITNESS_SOURCE_DIR}/src/third_party
    LIBS w1tn3ss w1rewind_static
    OUTPUT_SUBDIR test/w1tn3ss
)
