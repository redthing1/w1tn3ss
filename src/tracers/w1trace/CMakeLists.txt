cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TracerConfig.cmake)

create_tracer_targets(w1trace
    "preload.cpp;trace_tracer.cpp;trace_collector.cpp"
)

foreach(target w1trace_qbdipreload w1trace_static)
    if(TARGET ${target})
        target_link_libraries(${target} PUBLIC w1formats)
    endif()
endforeach()
