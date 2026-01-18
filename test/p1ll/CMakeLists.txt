cmake_minimum_required(VERSION 3.16)

add_subdirectory(core)

if(WITNESS_ASMR)
    add_subdirectory(heur)
endif()
