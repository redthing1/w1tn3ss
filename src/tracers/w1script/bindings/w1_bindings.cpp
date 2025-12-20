#include "w1_bindings.hpp"

#include "abi.hpp"
#include "api.hpp"
#include "dump.hpp"
#include "gadget.hpp"
#include "hook.hpp"
#include "inst.hpp"
#include "mem.hpp"
#include "module.hpp"
#include "output.hpp"
#include "p1ll.hpp"
#include "reg.hpp"
#include "root.hpp"
#include "symbol.hpp"
#include "util.hpp"
#include "vm.hpp"

namespace w1::tracers::script::bindings {

bool setup_w1_bindings(
    sol::state& lua,
    runtime::script_context& context,
    runtime::callback_registry& callback_registry,
    runtime::api_manager& api_manager,
    runtime::callback_store& vm_callback_store
) {
  sol::table w1_module = lua.create_table();

  setup_root_bindings(lua, w1_module, context, callback_registry, api_manager);
  setup_util_bindings(lua, w1_module);
  setup_inst_bindings(lua, w1_module);
  setup_mem_bindings(lua, w1_module, context);
  setup_reg_bindings(lua, w1_module);
  setup_module_bindings(lua, w1_module, context, api_manager);
  setup_symbol_bindings(lua, w1_module, context, api_manager);
  setup_api_bindings(lua, w1_module, api_manager, callback_registry);
  setup_hook_bindings(lua, w1_module, context);
  setup_abi_bindings(lua, w1_module);
  setup_dump_bindings(lua, w1_module);
  setup_gadget_bindings(lua, w1_module, context);
  setup_output_bindings(lua, w1_module, context);
  setup_p1ll_bindings(lua, w1_module, context);
  setup_vm_bindings(lua, w1_module, context, vm_callback_store);

  lua["w1"] = w1_module;
  return true;
}

} // namespace w1::tracers::script::bindings
