w1_dep_redlog()

w1_add_static_library(w1base
    arch_spec.cpp
    env_config.cpp
    module_identity.cpp
    signal_handler.cpp
)
add_library(w1::base ALIAS w1base)

target_link_libraries(w1base PUBLIC redlog::redlog)
