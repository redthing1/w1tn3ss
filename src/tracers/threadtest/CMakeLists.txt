cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TracerConfig.cmake)

set(THREADTEST_SOURCES
    preload.cpp
    threadtest_tracer.cpp
)

create_tracer_targets(threadtest "${THREADTEST_SOURCES}")
