w1_dep_qbdi()

w1_add_static_library(w1runtime
    module_catalog.cpp
    memory_reader.cpp
    register_capture.cpp
    stack_capture.cpp
    thread_catalog.cpp
    process_observer.cpp
)
add_library(w1::runtime ALIAS w1runtime)

target_link_libraries(w1runtime PUBLIC QBDI::QBDI w1monitor)
