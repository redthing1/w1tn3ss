#pragma once

#include <sol/sol.hpp>

#include <string>

namespace w1::tracers::script::bindings {

void setup_util_bindings(sol::state& lua, sol::table& w1_module);
std::string lua_table_to_json(const sol::table& lua_table);

} // namespace w1::tracers::script::bindings
