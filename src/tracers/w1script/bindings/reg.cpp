#include "reg.hpp"

#include "w1tn3ss/util/register_capture.hpp"

namespace w1::tracers::script::bindings {

void setup_reg_bindings(sol::state& lua, sol::table& w1_module) {
  sol::table reg = lua.create_table();

  reg.set_function("get", [](QBDI::GPRState* gpr, const std::string& name) -> sol::optional<uint64_t> {
    if (!gpr) {
      return sol::nullopt;
    }

    w1::util::register_state state = w1::util::register_capturer::capture(gpr);
    uint64_t value = 0;
    if (!state.get_register(name, value)) {
      return sol::nullopt;
    }
    return value;
  });

  reg.set_function("pc", [](QBDI::GPRState* gpr) -> sol::optional<uint64_t> {
    if (!gpr) {
      return sol::nullopt;
    }
    w1::util::register_state state = w1::util::register_capturer::capture(gpr);
    return state.get_instruction_pointer();
  });

  reg.set_function("sp", [](QBDI::GPRState* gpr) -> sol::optional<uint64_t> {
    if (!gpr) {
      return sol::nullopt;
    }
    w1::util::register_state state = w1::util::register_capturer::capture(gpr);
    return state.get_stack_pointer();
  });

  w1_module["reg"] = reg;
}

} // namespace w1::tracers::script::bindings
