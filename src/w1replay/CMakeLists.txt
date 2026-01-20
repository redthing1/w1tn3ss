w1_dep_lief()
w1_dep_gdbstub()

find_package(Threads REQUIRED)

w1_add_executable(w1replay
    main.cpp
    asmr_block_decoder.cpp
    module_image.cpp
    module_image_lief.cpp
    module_source.cpp
    gdb/adapter.cpp
    gdb/loaded_libraries_provider.cpp
    gdb/triple_utils.cpp
    gdb/components/regs_component.cpp
    gdb/components/mem_component.cpp
    gdb/components/run_component.cpp
    gdb/components/breakpoints_component.cpp
    gdb/components/threads_component.cpp
    gdb/components/host_info_component.cpp
    gdb/components/memory_layout_component.cpp
    gdb/components/libraries_component.cpp
    gdb/components/loaded_libraries_component.cpp
    gdb/components/process_info_component.cpp
    gdb/components/offsets_component.cpp
    gdb/components/register_info_component.cpp
    gdb/lldb/darwin_loaded_libraries.cpp
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

target_link_libraries(w1replay PRIVATE
    w1base
    w1rewind_replay
    gdbstub::gdbstub
    Threads::Threads
    w1::lief
)

if(TARGET w1asmr)
    target_link_libraries(w1replay PRIVATE w1asmr)
endif()

install(TARGETS w1replay RUNTIME DESTINATION bin COMPONENT ${W1_INSTALL_COMPONENT})
