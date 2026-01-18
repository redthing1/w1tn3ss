cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TracerConfig.cmake)

set(W1REWIND_SOURCES
    preload.cpp
    rewind_config.cpp
    rewind_config.hpp
    rewind_recorder.cpp
    rewind_recorder.hpp
    rewind_tracer.cpp
    rewind_tracer.hpp
)

create_tracer_targets(w1rewind "${W1REWIND_SOURCES}")

foreach(target w1rewind_qbdipreload w1rewind_static)
    if(TARGET ${target})
        target_link_libraries(${target} PUBLIC w1rewind_record)
    endif()
endforeach()
