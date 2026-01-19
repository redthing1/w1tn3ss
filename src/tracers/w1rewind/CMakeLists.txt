set(W1REWIND_SOURCES
    preload.cpp
    rewind_config.cpp
    rewind_config.hpp
    rewind_recorder.cpp
    rewind_recorder.hpp
    rewind_tracer.cpp
    rewind_tracer.hpp
)

w1_add_tracer(w1rewind
    SOURCES ${W1REWIND_SOURCES}
    LIBS w1rewind_record
)
