set(W1REWIND_SOURCES
    memory_filter.cpp
    memory_filter.hpp
    memory_access_builder.cpp
    memory_access_builder.hpp
    module_table_builder.cpp
    module_table_builder.hpp
    recording_engine.cpp
    recording_engine.hpp
    register_delta_builder.cpp
    register_delta_builder.hpp
    register_schema.cpp
    register_schema.hpp
    snapshot_builder.cpp
    snapshot_builder.hpp
    preload.cpp
    rewind_config.cpp
    rewind_config.hpp
    rewind_recorder.cpp
    rewind_recorder.hpp
    rewind_tracer.cpp
    rewind_tracer.hpp
    stack_window_policy.cpp
    stack_window_policy.hpp
    target_environment_provider.cpp
    target_environment_provider.hpp
    trace_emitter.cpp
    trace_emitter.hpp
)

w1_add_tracer(w1rewind
    SOURCES ${W1REWIND_SOURCES}
    LIBS w1rewind_record w1rewind_trace
)
