w1_dep_nlohmann_json()

w1_add_static_library(w1formats
    jsonl_writer.cpp
)
add_library(w1::formats ALIAS w1formats)

target_link_libraries(w1formats PUBLIC nlohmann_json::nlohmann_json)
