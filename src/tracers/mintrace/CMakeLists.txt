cmake_minimum_required(VERSION 3.16)

include(${CMAKE_SOURCE_DIR}/cmake/TracerConfig.cmake)

create_tracer_targets(mintrace "preload.cpp")