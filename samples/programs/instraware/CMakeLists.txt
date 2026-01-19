set(INSTRAWARE_COMMON_SOURCES
    instraware_common.cpp
)

function(add_instraware_target target_name source_file)
    add_executable(${target_name} ${source_file} ${INSTRAWARE_COMMON_SOURCES})
    w1_target_defaults(${target_name})
    target_include_directories(${target_name} PRIVATE ${CMAKE_CURRENT_LIST_DIR})
    set_target_properties(${target_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${samples_output_dir}
    )
endfunction()

add_instraware_target(instraware_qbdi_rai instraware_qbdi_rai.cpp)
add_instraware_target(instraware_qbdi_stack instraware_qbdi_stack.cpp)
add_instraware_target(instraware_qbdi_smc instraware_qbdi_smc.cpp)
add_instraware_target(instraware_qbdi_fault instraware_qbdi_fault.cpp)

target_compile_options(instraware_qbdi_rai PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-fno-omit-frame-pointer -fno-optimize-sibling-calls>
    $<$<CXX_COMPILER_ID:MSVC>:/Oy- /Ob0>
)

target_compile_options(instraware_qbdi_stack PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-fno-omit-frame-pointer -fno-optimize-sibling-calls>
    $<$<CXX_COMPILER_ID:MSVC>:/Oy- /Ob0>
)
