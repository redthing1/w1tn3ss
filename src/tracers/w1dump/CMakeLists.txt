cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TracerConfig.cmake)

create_tracer_targets(w1dump
    "preload.cpp;dump_tracer.cpp"
)

foreach(target w1dump_qbdipreload w1dump_static)
    if(TARGET ${target})
        target_link_libraries(${target} PUBLIC w1dump)
    endif()
endforeach()
