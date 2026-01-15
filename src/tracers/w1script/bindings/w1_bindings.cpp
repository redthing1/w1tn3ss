#include "w1_bindings.hpp"

#include "abi.hpp"
#include "inst.hpp"
#include "mem.hpp"
#include "module.hpp"
#include "output.hpp"
#include "reg.hpp"
#include "root.hpp"
#include "symbol.hpp"
#include "util.hpp"

namespace w1::tracers::script::bindings {

bool setup_w1_bindings(
    sol::state& lua, runtime::script_context& context, runtime::callback_registry& callback_registry
) {
  sol::table w1_module = lua.create_table();

  setup_root_bindings(lua, w1_module, context, callback_registry);
  setup_util_bindings(lua, w1_module, context.thread_id());
  setup_inst_bindings(lua, w1_module);
  setup_mem_bindings(lua, w1_module, context);
  setup_reg_bindings(lua, w1_module);
  setup_module_bindings(lua, w1_module, context);
  setup_symbol_bindings(lua, w1_module, context);
  setup_output_bindings(lua, w1_module, context);
  setup_abi_bindings(lua, w1_module, context);

  lua["w1"] = w1_module;
  return true;
}

} // namespace w1::tracers::script::bindings
