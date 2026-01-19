w1_dep_asmr()

if(NOT WITNESS_ASMR)
    message(STATUS "w1asmr disabled (WITNESS_ASMR=OFF)")
else()
    w1_add_static_library(w1asmr
        asmr.cpp
        arch.cpp
    )
    add_library(w1::asmr ALIAS w1asmr)

    target_link_libraries(w1asmr PUBLIC w1::asmr_deps)
endif()
