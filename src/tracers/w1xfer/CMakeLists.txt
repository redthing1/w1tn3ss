w1_add_tracer(w1xfer
    SOURCES
        entrypoints/preload.cpp
        thread/transfer_tracer.cpp
        engine/transfer_engine.cpp
        io/transfer_writer_jsonl.cpp
    LIBS w1analysis w1formats
)
