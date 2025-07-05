#pragma once

#include <sol/sol.hpp>

namespace w1::tracers::script::bindings {

/**
 * @brief setup module analysis functions in lua environment
 * @details provides clean api for module discovery and address-to-module mapping
 */
void setup_module_analysis(sol::state& lua, sol::table& w1_module);

} // namespace w1::tracers::script::bindings