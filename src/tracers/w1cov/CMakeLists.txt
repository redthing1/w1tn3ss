cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TracerConfig.cmake)

create_tracer_targets(w1cov
    "preload.cpp;coverage_tracer.cpp;coverage_collector.cpp;coverage_module_tracker.cpp;coverage_runtime.cpp;coverage_thread_tracer.cpp;coverage_thread_session.cpp"
)
