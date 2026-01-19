w1_dep_redlog()
w1_dep_zstd()

add_library(w1rewind_format INTERFACE)
add_library(w1rewind::format ALIAS w1rewind_format)
add_library(w1::rewind::format ALIAS w1rewind_format)

target_include_directories(w1rewind_format
    INTERFACE $<BUILD_INTERFACE:${W1_SOURCE_DIR}/src>
)

w1_add_static_library(w1rewind_record
    record/trace_writer.cpp
    record/trace_builder.cpp
)
add_library(w1rewind::record ALIAS w1rewind_record)
add_library(w1::rewind::record ALIAS w1rewind_record)

target_link_libraries(w1rewind_record PUBLIC w1base w1rewind_format redlog::redlog w1::zstd)

w1_add_static_library(w1rewind_replay
    replay/trace_reader.cpp
    replay/trace_index.cpp
    replay/trace_cursor.cpp
    replay/replay_context.cpp
    replay/replay_state.cpp
    replay/replay_state_applier.cpp
    replay/replay_checkpoint.cpp
    replay/replay_flow_cursor.cpp
    replay/replay_instruction_cursor.cpp
    replay/replay_session.cpp
)
add_library(w1rewind::replay ALIAS w1rewind_replay)
add_library(w1::rewind::replay ALIAS w1rewind_replay)

target_link_libraries(w1rewind_replay PUBLIC w1base w1rewind_format redlog::redlog w1::zstd)
