w1_add_static_library(w1h00k_reloc
    reloc/relocator.cpp
)

w1_add_static_library(w1h00k_os
    os/os.cpp
)

w1_add_static_library(w1h00k_resolve
    resolve/resolve.cpp
)

w1_add_static_library(w1h00k_memory
    memory/memory.cpp
)

w1_add_static_library(w1h00k_patcher
    patcher/patcher.cpp
)

w1_add_static_library(w1h00k_backend
    backend/backend_registry.cpp
)

w1_add_static_library(w1h00k_core
    core/hook_manager.cpp
    core/hook_transaction.cpp
)

w1_add_static_library(w1h00k
    hook.cpp
    errors.cpp
)
add_library(w1::h00k ALIAS w1h00k)

target_link_libraries(w1h00k_backend
    PUBLIC
        w1h00k_reloc
        w1h00k_resolve
        w1h00k_memory
        w1h00k_patcher
)

target_link_libraries(w1h00k_resolve
    PUBLIC
        w1h00k_os
)

target_link_libraries(w1h00k_core
    PUBLIC
        w1h00k_backend
)

target_link_libraries(w1h00k
    PUBLIC
        w1h00k_core
        w1base
)
