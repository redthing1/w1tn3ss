w1_add_static_library(w1monitor
    monitor_factory.cpp
    backend/null/null_module_monitor.cpp
    backend/null/null_thread_monitor.cpp
)
add_library(w1::monitor ALIAS w1monitor)

target_link_libraries(w1monitor PUBLIC w1base)
