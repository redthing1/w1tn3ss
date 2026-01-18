cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TracerConfig.cmake)
create_tracer_targets(w1xfer
    "preload.cpp;transfer_tracer.cpp;transfer_pipeline.cpp;transfer_writer_jsonl.cpp"
)

foreach(target w1xfer_qbdipreload w1xfer_static)
    if(TARGET ${target})
        target_link_libraries(${target} PUBLIC w1analysis w1formats)
    endif()
endforeach()
