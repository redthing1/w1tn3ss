cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TracerConfig.cmake)

create_tracer_targets(threadtest
    "preload.cpp;threadtest_tracer.cpp;thread_context.cpp;thread_manager.cpp;thread_hook.cpp"
)

if(TARGET threadtest_qbdipreload)
    target_link_libraries(threadtest_qbdipreload PRIVATE plthook::plthook)
endif()

if(TARGET threadtest_static)
    target_link_libraries(threadtest_static PRIVATE plthook::plthook)
endif()
