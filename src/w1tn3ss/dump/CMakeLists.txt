# dump module
add_library(w1tn3ss_dump STATIC
    process_dumper.cpp
    memory_dumper.cpp
    register_dumper.cpp
)

target_include_directories(w1tn3ss_dump PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
)

target_link_libraries(w1tn3ss_dump PUBLIC
    common
    redlog
    QBDI::QBDI
    nlohmann_json::nlohmann_json
)