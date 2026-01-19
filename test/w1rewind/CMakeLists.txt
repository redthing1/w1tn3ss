cmake_minimum_required(VERSION 3.16)

include(${W1_SOURCE_DIR}/cmake/TestConfig.cmake)

set(W1REWIND_TEST_SOURCES
    ${W1_SOURCE_DIR}/test/common/test_main.cpp
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
        ${W1_SOURCE_DIR}/src
        ${W1_SOURCE_DIR}/src/third_party
        ${W1_SOURCE_DIR}/test
    LIBS
        ${W1REWIND_TEST_LIBS}
    OUTPUT_SUBDIR test/w1rewind
)
