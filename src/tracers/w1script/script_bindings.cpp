#include "script_bindings.hpp"
#include <redlog.hpp>

namespace w1::tracers::script {

void setup_qbdi_bindings(sol::state& lua) {
  auto log = redlog::get_logger("w1script.bindings");
  log.inf("setting up modular QBDI bindings");

  // Create the main w1 module
  sol::table w1_module = lua.create_table();

  // Setup all binding modules in logical order
  log.dbg("setting up core types and enums");
  bindings::setup_core_types(lua, w1_module);

  log.dbg("setting up register access functions");
  bindings::setup_register_access(lua, w1_module);

  log.dbg("setting up VM control functions");
  bindings::setup_vm_control(lua, w1_module);

  log.dbg("setting up memory analysis functions");
  bindings::setup_memory_analysis(lua, w1_module);

  log.dbg("setting up module analysis functions");
  bindings::setup_module_analysis(lua, w1_module);

  log.dbg("setting up utility functions");
  bindings::setup_utilities(lua, w1_module);

  log.dbg("setting up callback system");
  bindings::setup_callback_system(lua, w1_module);

  // Register the w1 module with the Lua state
  lua["w1"] = w1_module;

  log.inf("all QBDI bindings registered successfully");
  log.dbg(
      "available modules: core_types, register_access, vm_control, memory_analysis, module_analysis, utilities, "
      "callback_system"
  );
}

} // namespace w1::tracers::script
