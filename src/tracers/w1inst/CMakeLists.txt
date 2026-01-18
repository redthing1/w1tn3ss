cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TracerConfig.cmake)

create_tracer_targets(w1inst
    "preload.cpp;instruction_tracer.cpp;instruction_collector.cpp"
)

foreach(target w1inst_qbdipreload w1inst_static)
    if(TARGET ${target})
        target_link_libraries(${target} PUBLIC w1formats)
    endif()
endforeach()
