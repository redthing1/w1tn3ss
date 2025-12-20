#pragma once

#include "../runtime/callback_store.hpp"
#include "../runtime/script_context.hpp"

#include <sol/sol.hpp>

namespace w1::tracers::script::bindings {

void setup_vm_bindings(
    sol::state& lua,
    sol::table& w1_module,
    runtime::script_context& context,
    runtime::callback_store& callback_store
);

} // namespace w1::tracers::script::bindings
