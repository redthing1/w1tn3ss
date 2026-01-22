w1_add_static_library(w1h00k_reloc
    reloc/relocator.cpp
    reloc/reloc_x86.cpp
    reloc/reloc_arm64.cpp
)
target_link_libraries(w1h00k_reloc PUBLIC w1asmr)

w1_add_static_library(w1h00k_os
    os/os.cpp
)

w1_add_static_library(w1h00k_resolve
    resolve/resolve.cpp
)

set(W1H00K_MEMORY_SOURCES "")
if(WIN32)
    list(APPEND W1H00K_MEMORY_SOURCES memory/memory_windows.cpp)
else()
    list(APPEND W1H00K_MEMORY_SOURCES memory/memory_posix.cpp)
endif()

w1_add_static_library(w1h00k_memory ${W1H00K_MEMORY_SOURCES})

set(W1H00K_PATCHER_SOURCES "")
if(WIN32)
    list(APPEND W1H00K_PATCHER_SOURCES patcher/patcher_windows.cpp)
else()
    list(APPEND W1H00K_PATCHER_SOURCES patcher/patcher_posix.cpp)
endif()

w1_add_static_library(w1h00k_patcher ${W1H00K_PATCHER_SOURCES})

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
