cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TracerConfig.cmake)

create_tracer_targets(gadgetdemo
    "preload.cpp;gadgetdemo_tracer.cpp"
)
