w1_add_static_library(w1instrument
    core/instrumentation_policy.cpp
    core/vm_controller.cpp
)
add_library(w1::instrument ALIAS w1instrument)

target_link_libraries(w1instrument PUBLIC w1runtime w1base)
