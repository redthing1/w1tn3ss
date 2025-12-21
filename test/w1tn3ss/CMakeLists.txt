cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)

add_executable(w1tn3ss_unit_tests
    test_main.cpp
    memory_reader_test.cpp
    module_registry_test.cpp
    event_router_test.cpp
    instrumentation_policy_test.cpp
    trace_session_smoke_test.cpp
    interval_test.cpp
    jsonl_writer_test.cpp
    symbol_lookup_test.cpp
    abi_dispatcher_test.cpp
)

target_include_directories(w1tn3ss_unit_tests PRIVATE
    ${WITNESS_SOURCE_DIR}/src
    ${WITNESS_SOURCE_DIR}/src/third_party
)

target_link_libraries(w1tn3ss_unit_tests PRIVATE
    w1tn3ss
)

set_target_properties(w1tn3ss_unit_tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test/w1tn3ss
)

apply_common_compile_options(w1tn3ss_unit_tests)
apply_windows_definitions(w1tn3ss_unit_tests)

add_test(
    NAME w1tn3ss_unit_tests
    COMMAND w1tn3ss_unit_tests
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/test/w1tn3ss
)
