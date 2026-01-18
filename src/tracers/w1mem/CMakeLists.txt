cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TracerConfig.cmake)

create_tracer_targets(w1mem
    "preload.cpp;memory_tracer.cpp;memory_collector.cpp"
)

foreach(target w1mem_qbdipreload w1mem_static)
    if(TARGET ${target})
        target_link_libraries(${target} PUBLIC w1formats)
    endif()
endforeach()
