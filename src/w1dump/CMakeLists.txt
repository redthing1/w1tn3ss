w1_dep_redlog()

w1_add_static_library(w1dump
    memory_dumper.cpp
    process_dumper.cpp
    register_dumper.cpp
)
add_library(w1::dump ALIAS w1dump)

target_link_libraries(w1dump PUBLIC w1formats w1runtime redlog::redlog)
