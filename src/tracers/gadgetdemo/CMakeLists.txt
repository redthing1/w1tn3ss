cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TracerConfig.cmake)

create_tracer_targets(gadgetdemo
    "preload.cpp;gadgetdemo_tracer.cpp"
)

foreach(target gadgetdemo_qbdipreload gadgetdemo_static)
    if(TARGET ${target})
        target_link_libraries(${target} PUBLIC w1gadget)
    endif()
endforeach()
