#pragma once

#include "../runtime/callback_registry.hpp"
#include "../runtime/script_context.hpp"

#include <sol/sol.hpp>

namespace w1::tracers::script::bindings {

bool setup_w1_bindings(
    sol::state& lua, runtime::script_context& context, runtime::callback_registry& callback_registry
);

} // namespace w1::tracers::script::bindings
