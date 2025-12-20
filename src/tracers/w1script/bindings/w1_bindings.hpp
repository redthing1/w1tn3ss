#pragma once

#include "../runtime/api_manager.hpp"
#include "../runtime/callback_registry.hpp"
#include "../runtime/callback_store.hpp"
#include "../runtime/script_context.hpp"

#include <sol/sol.hpp>

namespace w1::tracers::script::bindings {

bool setup_w1_bindings(
    sol::state& lua,
    runtime::script_context& context,
    runtime::callback_registry& callback_registry,
    runtime::api_manager& api_manager,
    runtime::callback_store& vm_callback_store
);

} // namespace w1::tracers::script::bindings
