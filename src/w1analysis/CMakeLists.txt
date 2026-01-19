w1_add_static_library(w1analysis
    abi_dispatcher.cpp
    symbol_lookup.cpp
)
add_library(w1::analysis ALIAS w1analysis)

target_link_libraries(w1analysis PUBLIC w1runtime)
