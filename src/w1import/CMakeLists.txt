w1_dep_redlog()
w1_dep_lief()

set(W1IMPORT_SOURCES
    import_insertion.cpp
)

if(APPLE)
    list(APPEND W1IMPORT_SOURCES
        platform/macos/macos_import_inserter.cpp
        backend/macos/macho_processor.cpp
    )
elseif(WIN32)
    list(APPEND W1IMPORT_SOURCES
        platform/windows/windows_import_inserter.cpp
    )
else()
    list(APPEND W1IMPORT_SOURCES
        platform/linux/linux_import_inserter.cpp
    )
endif()

w1_add_static_library(w1import ${W1IMPORT_SOURCES})
add_library(w1::import ALIAS w1import)

target_link_libraries(w1import PUBLIC w1::lief)
target_link_libraries(w1import PRIVATE redlog::redlog)
