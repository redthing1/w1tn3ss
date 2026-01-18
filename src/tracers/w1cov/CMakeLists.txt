cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TracerConfig.cmake)

create_tracer_targets(w1cov
    "preload.cpp;coverage_tracer.cpp;coverage_collector.cpp;coverage_module_tracker.cpp"
)

foreach(target w1cov_qbdipreload w1cov_static)
    if(TARGET ${target})
        target_link_libraries(${target} PUBLIC w1formats)
    endif()
endforeach()
