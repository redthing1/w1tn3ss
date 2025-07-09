cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TracerConfig.cmake)
include(${WITNESS_SOURCE_DIR}/cmake/LIEFConfig.cmake)

create_tracer_targets(w1xfer
    "preload.cpp;transfer_tracer.cpp;transfer_collector.cpp;symbol_enricher.cpp"
)

# Apply LIEF configuration to w1xfer targets
if(WITNESS_BUILD_SHARED)
    configure_target_with_lief(w1xfer_qbdipreload)
endif()

if(WITNESS_BUILD_STATIC)
    configure_target_with_lief(w1xfer_static)
endif()