cmake_minimum_required(VERSION 3.16)

add_subdirectory(core)

if(P1LL_BUILD_ASMR)
    add_subdirectory(asmr)
endif()
