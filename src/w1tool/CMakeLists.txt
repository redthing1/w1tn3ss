w1_dep_lief()

w1_add_executable(w1tool
    main.cpp
    commands/debug.cpp
    commands/inject.cpp
    commands/insert_library.cpp
    commands/inspect.cpp
    commands/cover.cpp
    commands/rewind.cpp
    commands/read_drcov.cpp
    commands/dump.cpp
    commands/read_dump.cpp
    commands/tracer.cpp
    tracer_discovery.cpp
)

target_link_libraries(w1tool PRIVATE
    w1base
    w1dump
    w1formats
    w1import
    w1nj3ct
    w1debugger
    w1::lief
)

install(TARGETS w1tool RUNTIME DESTINATION bin COMPONENT ${W1_INSTALL_COMPONENT})
