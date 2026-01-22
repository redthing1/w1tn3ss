w1_add_tracer(w1cov
    SOURCES
        preload.cpp
        instrument/coverage_runtime.cpp
        instrument/coverage_recorder.cpp
        engine/coverage_engine.cpp
        engine/coverage_store.cpp
        engine/coverage_exporter.cpp
    LIBS w1formats
)
