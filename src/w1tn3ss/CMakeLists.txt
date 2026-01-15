cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)

add_library(w1tn3ss STATIC
    w1tn3ss.cpp
    analysis/abi_dispatcher.cpp
    analysis/symbol_lookup.cpp
    core/instrumentation_policy.cpp
    core/vm_controller.cpp
    dump/memory_dumper.cpp
    dump/process_dumper.cpp
    dump/register_dumper.cpp
    gadget/gadget_executor.cpp
    import_insertion/import_insertion.cpp
    io/jsonl_writer.cpp
    runtime/module_registry.cpp
    runtime/rewind/binary_trace_sink.cpp
    runtime/rewind/binary_trace_source.cpp
    runtime/rewind/trace_validator.cpp
    util/env_config.cpp
    util/memory_reader.cpp
    util/module_identity.cpp
    util/register_capture.cpp
    util/signal_handler.cpp
    util/stack_capture.cpp
)

target_include_directories(w1tn3ss PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${WITNESS_SOURCE_DIR}/src
)

target_link_libraries(w1tn3ss PUBLIC
    QBDI_static
    redlog::redlog
    nlohmann_json::nlohmann_json
)

apply_common_compile_options(w1tn3ss)
set_standard_output_dirs(w1tn3ss)
apply_platform_linking(w1tn3ss)
configure_target_with_lief(w1tn3ss)

set_target_properties(w1tn3ss PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(APPLE)
    target_sources(w1tn3ss PRIVATE
        import_insertion/platform/macos/macos_import_inserter.cpp
        import_insertion/backend/macos/macho_processor.cpp
    )
elseif(WIN32)
    target_sources(w1tn3ss PRIVATE
        import_insertion/platform/windows/windows_import_inserter.cpp
    )
else()
    target_sources(w1tn3ss PRIVATE
        import_insertion/platform/linux/linux_import_inserter.cpp
    )
endif()
