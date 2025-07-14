#pragma once

#include <sol/sol.hpp>
#include <memory>

namespace w1tn3ss::gadget {
class gadget_executor;
}

namespace w1::tracers::script::bindings {

void setup_gadget_execution(
    sol::state& lua, sol::table& w1_module, std::shared_ptr<w1tn3ss::gadget::gadget_executor> gadget_exec
);

} // namespace w1::tracers::script::bindings