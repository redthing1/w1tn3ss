#pragma once

#include <sol/sol.hpp>
#include <QBDI.h>

namespace w1::tracers::script::bindings {

void setup_reg_bindings(sol::state& lua, sol::table& w1_module);

} // namespace w1::tracers::script::bindings
