#pragma once

#include "../runtime/api_manager.hpp"
#include "../runtime/callback_registry.hpp"

#include <sol/sol.hpp>

namespace w1::tracers::script::bindings {

void setup_api_bindings(
    sol::state& lua,
    sol::table& w1_module,
    runtime::api_manager& api_manager,
    runtime::callback_registry& callback_registry
);

} // namespace w1::tracers::script::bindings
