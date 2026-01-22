set(W1MONITOR_SOURCES
    monitor_factory.cpp
    backend/null/null_module_monitor.cpp
    backend/null/null_thread_monitor.cpp
)

if(APPLE)
    list(APPEND W1MONITOR_SOURCES
        backend/darwin/darwin_module_monitor.cpp
        backend/darwin/darwin_thread_monitor.cpp
    )
endif()

w1_add_static_library(w1monitor ${W1MONITOR_SOURCES})
add_library(w1::monitor ALIAS w1monitor)

target_link_libraries(w1monitor PUBLIC w1base w1h00k)
