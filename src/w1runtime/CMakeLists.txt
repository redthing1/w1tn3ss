w1_dep_qbdi()

w1_add_static_library(w1runtime
    module_registry.cpp
    memory_reader.cpp
    register_capture.cpp
    stack_capture.cpp
)
add_library(w1::runtime ALIAS w1runtime)

target_link_libraries(w1runtime PUBLIC QBDI::QBDI)
