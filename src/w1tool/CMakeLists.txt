cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)

add_executable(w1tool
    main.cpp
    commands/inject.cpp
    commands/insert_library.cpp
    commands/inspect.cpp
    commands/cover.cpp
    commands/read_drcov.cpp
    commands/dump.cpp
    commands/read_dump.cpp
    commands/tracer.cpp
    tracer_discovery.cpp
)

set_target_properties(w1tool PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

target_include_directories(w1tool PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${WITNESS_SOURCE_DIR}/src
)

target_link_libraries(w1tool PRIVATE
    w1tn3ss
    w1tn3ss_dump
    w1nj3ct
    common
    redlog::redlog
)

apply_common_compile_options(w1tool)
apply_windows_definitions(w1tool)
configure_target_with_lief(w1tool)

install(TARGETS w1tool RUNTIME DESTINATION bin)