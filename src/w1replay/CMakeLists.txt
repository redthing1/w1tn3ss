cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)
include(${WITNESS_SOURCE_DIR}/cmake/LIEFConfig.cmake)

find_package(Threads REQUIRED)

add_executable(w1replay
    main.cpp
    asmr_block_decoder.cpp
    module_image.cpp
    module_image_lief.cpp
    module_source.cpp
    gdb/adapter.cpp
    gdb/adapter_components.cpp
    gdb/layout.cpp
    gdb/target_xml.cpp
    gdb/memory_merge.cpp
    gdb/memory_map.cpp
    gdb/value_codec.cpp
    gdb/stepper.cpp
    commands/checkpoint.cpp
    commands/inspect.cpp
    commands/server.cpp
    commands/threads.cpp
)

set_target_properties(w1replay PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

target_include_directories(w1replay PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(w1replay PRIVATE
    w1base
    w1rewind_replay
    gdbstub::gdbstub
    Threads::Threads
)

if(TARGET w1asmr)
    target_link_libraries(w1replay PRIVATE w1asmr)
endif()

apply_common_compile_options(w1replay)
apply_windows_definitions(w1replay)
configure_target_with_lief(w1replay)

install(TARGETS w1replay RUNTIME DESTINATION bin)
