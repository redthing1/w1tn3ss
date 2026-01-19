w1_dep_redlog()
w1_dep_qbdi()

w1_add_static_library(w1gadget
    gadget_executor.cpp
)
add_library(w1::gadget ALIAS w1gadget)

target_link_libraries(w1gadget PUBLIC QBDI::QBDI redlog::redlog)
