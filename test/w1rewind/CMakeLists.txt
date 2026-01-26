cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TestConfig.cmake)

set(W1REWIND_TEST_SOURCES
    ${WITNESS_SOURCE_DIR}/test/common/test_main.cpp
    rewind_trace_io_test.cpp
    rewind_recorder_recording_test.cpp
    rewind_recorder_block_recording_test.cpp
    rewind_recorder_helpers_test.cpp
    rewind_config_validation_test.cpp
    rewind_memory_filter_test.cpp
    rewind_memory_map_mapping_test.cpp
    rewind_mapping_state_test.cpp
    rewind_image_segment_utils_test.cpp
    rewind_module_event_test.cpp
    rewind_image_inventory_test.cpp
    rewind_snapshot_codec_test.cpp
    rewind_stack_window_policy_test.cpp
    rewind_trace_index_test.cpp
    rewind_history_window_test.cpp
    rewind_flow_extractor_test.cpp
    rewind_replay_position_test.cpp
    rewind_replay_cursor_property_test.cpp
    rewind_replay_cursor_test.cpp
    rewind_replay_session_position_test.cpp
    rewind_replay_run_invariants_test.cpp
    rewind_replay_cursor_semantics_test.cpp
    rewind_replay_instruction_cursor_test.cpp
    rewind_replay_checkpoint_test.cpp
    rewind_replay_session_test.cpp
    rewind_replay_state_applier_test.cpp
    rewind_replay_state_test.cpp
    rewind_minimal_trace_test.cpp
)

set(W1REWIND_TEST_LIBS
    w1rewind_record
    w1rewind_replay
)

if(TARGET w1rewind_static)
    list(APPEND W1REWIND_TEST_LIBS w1rewind_static)
elseif(TARGET w1rewind_qbdipreload)
    list(APPEND W1REWIND_TEST_LIBS w1rewind_qbdipreload)
endif()

w1_add_doctest_suite(w1rewind_unit_tests
    SOURCES ${W1REWIND_TEST_SOURCES}
    INCLUDE_DIRS
        ${WITNESS_SOURCE_DIR}/src
        ${WITNESS_SOURCE_DIR}/src/third_party
        ${WITNESS_SOURCE_DIR}/src/tracers/w1rewind
        ${WITNESS_SOURCE_DIR}/test
    LIBS
        ${W1REWIND_TEST_LIBS}
    OUTPUT_SUBDIR w1rewind
)
