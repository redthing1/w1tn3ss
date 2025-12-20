#pragma once

#include <sol/sol.hpp>

namespace w1::tracers::script::bindings {

void setup_dump_bindings(sol::state& lua, sol::table& w1_module);

} // namespace w1::tracers::script::bindings
