#pragma once

#include <sol/sol.hpp>

#include <string>

namespace w1::tracers::script::bindings {

void setup_util_bindings(sol::state& lua, sol::table& w1_module, uint64_t thread_id);
std::string lua_table_to_json(const sol::table& table);

} // namespace w1::tracers::script::bindings
