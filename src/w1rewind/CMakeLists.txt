w1_dep_redlog()
w1_dep_zstd()

w1_add_static_library(w1rewind_format
    format/register_numbering.cpp
    format/trace_validator.cpp
)
add_library(w1rewind::format ALIAS w1rewind_format)
add_library(w1::rewind::format ALIAS w1rewind_format)

target_include_directories(w1rewind_format
    PUBLIC $<BUILD_INTERFACE:${W1_SOURCE_DIR}/src>
)

target_link_libraries(w1rewind_format PUBLIC w1base redlog::redlog)

w1_add_static_library(w1rewind_trace
    trace/trace_reader.cpp
    trace/trace_index.cpp
    trace/replay_checkpoint.cpp
    trace/trace_file_writer.cpp
)
add_library(w1rewind::trace ALIAS w1rewind_trace)
add_library(w1::rewind::trace ALIAS w1rewind_trace)

target_link_libraries(w1rewind_trace PUBLIC w1base w1rewind_format redlog::redlog w1::zstd)

w1_add_static_library(w1rewind_record
    record/memory_map_utils.cpp
    record/trace_builder.cpp
)
add_library(w1rewind::record ALIAS w1rewind_record)
add_library(w1::rewind::record ALIAS w1rewind_record)

target_link_libraries(w1rewind_record PUBLIC w1base w1rewind_format redlog::redlog)

w1_add_static_library(w1rewind_replay
    replay/replay_context.cpp
    replay/replay_context_builder.cpp
    replay/memory_store.cpp
    replay/replay_state.cpp
    replay/replay_state_applier.cpp
    replay/replay_position.cpp
    replay/record_stream_cursor.cpp
    replay/flow_extractor.cpp
    replay/history_window.cpp
    replay/flow_cursor.cpp
    replay/stateful_flow_cursor.cpp
    replay/replay_instruction_cursor.cpp
    replay/replay_session.cpp
)
add_library(w1rewind::replay ALIAS w1rewind_replay)
add_library(w1::rewind::replay ALIAS w1rewind_replay)

target_link_libraries(w1rewind_replay PUBLIC w1base w1rewind_format w1rewind_trace redlog::redlog)
