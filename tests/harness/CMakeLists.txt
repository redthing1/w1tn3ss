cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TestConfig.cmake)

w1_add_harness_test(test_standalone_tracers
    SOURCES test_standalone_tracers.cpp
    INCLUDE_DIRS ${WITNESS_SOURCE_DIR}/src
    LIBS w1cov_static w1xfer_static
    OUTPUT_SUBDIR test/harness
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
    LIBS w1gadget
    OUTPUT_SUBDIR test/harness
)

w1_add_harness_test(test_rewind_format
    SOURCES test_rewind_format.cpp
    INCLUDE_DIRS ${WITNESS_SOURCE_DIR}/src
    LIBS w1rewind_record w1rewind_replay
    OUTPUT_SUBDIR test/harness
)

set_tests_properties(test_gadget_executor PROPERTIES
    LABELS "unit;gadget;executor"
)
