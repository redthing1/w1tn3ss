cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)

add_library(w1rewind_format INTERFACE)
target_include_directories(w1rewind_format
    INTERFACE $<BUILD_INTERFACE:${WITNESS_SOURCE_DIR}/src>
)

find_package(ZSTD QUIET)
set(W1_REWIND_ZSTD_TARGET "")
set(W1_REWIND_ZSTD_LIBRARIES "")
set(W1_REWIND_ZSTD_INCLUDE_DIRS "")
if(ZSTD_FOUND)
    if(TARGET ZSTD::ZSTD)
        set(W1_REWIND_ZSTD_TARGET ZSTD::ZSTD)
    elseif(TARGET zstd::libzstd)
        set(W1_REWIND_ZSTD_TARGET zstd::libzstd)
    elseif(TARGET zstd::libzstd_static)
        set(W1_REWIND_ZSTD_TARGET zstd::libzstd_static)
    elseif(TARGET zstd::libzstd_shared)
        set(W1_REWIND_ZSTD_TARGET zstd::libzstd_shared)
    elseif(ZSTD_LIBRARIES AND ZSTD_INCLUDE_DIRS)
        set(W1_REWIND_ZSTD_LIBRARIES ${ZSTD_LIBRARIES})
        set(W1_REWIND_ZSTD_INCLUDE_DIRS ${ZSTD_INCLUDE_DIRS})
    endif()
endif()

function(w1rewind_enable_zstd target)
    if(W1_REWIND_ZSTD_TARGET)
        target_link_libraries(${target} PRIVATE ${W1_REWIND_ZSTD_TARGET})
        target_compile_definitions(${target} PUBLIC W1_REWIND_HAVE_ZSTD=1)
    elseif(W1_REWIND_ZSTD_LIBRARIES)
        target_link_libraries(${target} PRIVATE ${W1_REWIND_ZSTD_LIBRARIES})
        target_include_directories(${target} PRIVATE ${W1_REWIND_ZSTD_INCLUDE_DIRS})
        target_compile_definitions(${target} PUBLIC W1_REWIND_HAVE_ZSTD=1)
    endif()
endfunction()

add_library(w1rewind_record STATIC
    record/trace_writer.cpp
    record/trace_builder.cpp
)

target_include_directories(w1rewind_record
    PUBLIC $<BUILD_INTERFACE:${WITNESS_SOURCE_DIR}/src>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(w1rewind_record PUBLIC w1base w1rewind_format redlog::redlog)

apply_common_compile_options(w1rewind_record)
apply_windows_definitions(w1rewind_record)
set_standard_output_dirs(w1rewind_record)

set_target_properties(w1rewind_record PROPERTIES POSITION_INDEPENDENT_CODE ON)

w1rewind_enable_zstd(w1rewind_record)

add_library(w1rewind_replay STATIC
    replay/trace_reader.cpp
    replay/trace_index.cpp
    replay/trace_cursor.cpp
    replay/replay_context.cpp
    replay/replay_state.cpp
    replay/replay_state_applier.cpp
    replay/replay_checkpoint.cpp
    replay/replay_flow_cursor.cpp
    replay/replay_instruction_cursor.cpp
    replay/replay_session.cpp
)

target_include_directories(w1rewind_replay
    PUBLIC $<BUILD_INTERFACE:${WITNESS_SOURCE_DIR}/src>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(w1rewind_replay PUBLIC w1base w1rewind_format redlog::redlog)

apply_common_compile_options(w1rewind_replay)
apply_windows_definitions(w1rewind_replay)
set_standard_output_dirs(w1rewind_replay)

set_target_properties(w1rewind_replay PROPERTIES POSITION_INDEPENDENT_CODE ON)

w1rewind_enable_zstd(w1rewind_replay)
