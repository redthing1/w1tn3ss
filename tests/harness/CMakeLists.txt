cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TestConfig.cmake)

w1_add_harness_test(test_standalone_tracers
    SOURCES test_standalone_tracers.cpp
    INCLUDE_DIRS ${WITNESS_SOURCE_DIR}/src
    LIBS w1cov_static w1xfer_static w1tn3ss redlog::redlog
    OUTPUT_SUBDIR tests
    ARGS all
)

if(WITNESS_SCRIPT)
    include(${WITNESS_SOURCE_DIR}/cmake/LuaConfig.cmake)
    configure_target_with_lua(test_standalone_tracers)
    target_link_libraries(test_standalone_tracers PRIVATE w1script_static)
endif()

if(WIN32 AND MSVC)
    include(${WITNESS_SOURCE_DIR}/cmake/WindowsSymbolConfig.cmake)
    configure_windows_symbol_resolution(test_standalone_tracers)
endif()

w1_add_harness_test(test_gadget_executor
    SOURCES test_gadget_executor.cpp
    INCLUDE_DIRS ${WITNESS_SOURCE_DIR}/src
    LIBS w1tn3ss QBDI_static redlog::redlog
    OUTPUT_SUBDIR tests
)

set_tests_properties(test_gadget_executor PROPERTIES
    LABELS "unit;gadget;executor"
)
