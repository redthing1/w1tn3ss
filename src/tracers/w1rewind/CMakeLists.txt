cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TracerConfig.cmake)

set(W1REWIND_SOURCES
    preload.cpp
    rewind_config.cpp
    rewind_config.hpp
    rewind_session.cpp
    rewind_session.hpp
    rewind_tracer.cpp
    rewind_tracer.hpp
)

create_tracer_targets(w1rewind "${W1REWIND_SOURCES}")
