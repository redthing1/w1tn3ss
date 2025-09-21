cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/TracerConfig.cmake)

set(THREADTEST_SOURCES
    preload.cpp
    threadtest_tracer.cpp
    thread_context.cpp
    thread_manager.cpp
    thread_hook.cpp
)

if(APPLE)
    list(APPEND THREADTEST_SOURCES thread_hook_darwin.cpp)
elseif(WIN32)
    list(APPEND THREADTEST_SOURCES thread_hook_windows.cpp)
elseif(UNIX)
    list(APPEND THREADTEST_SOURCES thread_hook_linux.cpp)
else()
    list(APPEND THREADTEST_SOURCES thread_hook_stub.cpp)
endif()

create_tracer_targets(threadtest "${THREADTEST_SOURCES}")

if(TARGET threadtest_qbdipreload)
    target_link_libraries(threadtest_qbdipreload PRIVATE plthook::plthook)
endif()

if(TARGET threadtest_static)
    target_link_libraries(threadtest_static PRIVATE plthook::plthook)
endif()

if(WIN32)
    if(TARGET threadtest_qbdipreload)
        target_link_libraries(threadtest_qbdipreload PRIVATE funchook::funchook)
    endif()
    if(TARGET threadtest_static)
        target_link_libraries(threadtest_static PRIVATE funchook::funchook)
    endif()
endif()
