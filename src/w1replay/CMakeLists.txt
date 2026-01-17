cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)

add_executable(w1replay
    main.cpp
    commands/inspect.cpp
    commands/threads.cpp
)

set_target_properties(w1replay PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

target_include_directories(w1replay PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${WITNESS_SOURCE_DIR}/src
)

target_link_libraries(w1replay PRIVATE
    w1tn3ss
    common
    redlog::redlog
)

apply_common_compile_options(w1replay)
apply_windows_definitions(w1replay)

install(TARGETS w1replay RUNTIME DESTINATION bin)
