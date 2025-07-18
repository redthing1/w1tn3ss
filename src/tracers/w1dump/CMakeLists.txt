cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TracerConfig.cmake)

create_tracer_targets(w1dump
    "preload.cpp;dump_tracer.cpp"
)

# link w1tn3ss_dump library to both targets if they exist
if(TARGET w1dump_qbdipreload)
    target_link_libraries(w1dump_qbdipreload PRIVATE w1tn3ss_dump)
endif()

if(TARGET w1dump_static)
    target_link_libraries(w1dump_static PRIVATE w1tn3ss_dump)
endif()