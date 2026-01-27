w1_dep_lief()
w1_dep_gdbstub()

find_package(Threads REQUIRED)

w1_add_executable(w1replay
    cli/main.cpp
    cli/commands/checkpoint.cpp
    cli/commands/coverage.cpp
    cli/commands/inspect.cpp
    cli/commands/server.cpp
    cli/commands/summary.cpp
    cli/commands/threads.cpp
    modules/asmr_block_decoder.cpp
    modules/address_index.cpp
    modules/address_read_cursor.cpp
    modules/image_blob_reader.cpp
    modules/image_bytes.cpp
    modules/image_layout_from_metadata.cpp
    modules/trace_metadata_provider.cpp
    modules/composite_image_provider.cpp
    modules/file_image_reader.cpp
    modules/image_layout_provider.cpp
    modules/lief_image_layout_provider.cpp
    modules/path_resolver.cpp
    trace_loader/trace_loader.cpp
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
    gdb/components/auxv_component.cpp
    gdb/components/offsets_component.cpp
    gdb/components/register_info_component.cpp
    gdb/lldb/darwin_loaded_libraries.cpp
    gdb/layout.cpp
    gdb/target_xml.cpp
    gdb/memory_map.cpp
    memory/memory_view.cpp
    gdb/value_codec.cpp
    gdb/stepper.cpp
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

install(TARGETS w1replay RUNTIME DESTINATION bin COMPONENT ${WITNESS_INSTALL_COMPONENT})
