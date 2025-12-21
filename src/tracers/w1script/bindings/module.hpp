#pragma once

#include "../runtime/script_context.hpp"

#include <sol/sol.hpp>

namespace w1::tracers::script::bindings {

void setup_module_bindings(sol::state& lua, sol::table& w1_module, runtime::script_context& context);

} // namespace w1::tracers::script::bindings
