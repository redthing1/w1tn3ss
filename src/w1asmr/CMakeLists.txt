cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)

if(NOT WITNESS_ASMR)
    message(STATUS "w1asmr disabled (WITNESS_ASMR=OFF)")
else()
    add_library(w1asmr STATIC
        asmr.cpp
        arch.cpp
    )

    target_include_directories(w1asmr
        PUBLIC $<BUILD_INTERFACE:${WITNESS_SOURCE_DIR}/src>
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
    )

    target_link_libraries(w1asmr PUBLIC w1base capstone::capstone keystone::keystone)

    if(DEFINED WITNESS_ASMR_CAPSTONE_INCLUDE_DIR)
        target_include_directories(w1asmr PRIVATE ${WITNESS_ASMR_CAPSTONE_INCLUDE_DIR})
    endif()
    if(DEFINED WITNESS_ASMR_KEYSTONE_INCLUDE_DIR)
        target_include_directories(w1asmr PRIVATE ${WITNESS_ASMR_KEYSTONE_INCLUDE_DIR})
    endif()

    target_compile_definitions(w1asmr PUBLIC WITNESS_ASMR_ENABLED=1)

    apply_common_compile_options(w1asmr)
    apply_windows_definitions(w1asmr)
    apply_platform_linking(w1asmr)
    set_standard_output_dirs(w1asmr)

    set_target_properties(w1asmr PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()
