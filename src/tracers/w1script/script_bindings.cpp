#include "script_bindings.hpp"
#include <redlog.hpp>
#include "bindings/output.hpp"

namespace w1::tracers::script {

void setup_qbdi_bindings(
    sol::state& lua, sol::table& tracer_table, std::shared_ptr<bindings::api_analysis_manager>& api_manager,
    std::shared_ptr<w1::hooking::hook_manager>& hook_manager,
    std::shared_ptr<w1tn3ss::gadget::gadget_executor>& gadget_executor
) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.inf("setting up modular qbdi bindings");

  // create the main w1 module
  sol::table w1_module = lua.create_table();

  // setup all binding modules in logical order
  logger.dbg("setting up core types and enums");
  bindings::setup_core_types(lua, w1_module);

  logger.dbg("setting up register access functions");
  bindings::setup_register_access(lua, w1_module);

  logger.dbg("setting up vm control functions");
  bindings::setup_vm_control(lua, w1_module);

  logger.dbg("setting up vm core functions");
  bindings::setup_vm_core(lua, w1_module);

  logger.dbg("setting up memory analysis functions");
  bindings::setup_memory_analysis(lua, w1_module);

  logger.dbg("setting up module analysis functions");
  bindings::setup_module_analysis(lua, w1_module);

  logger.dbg("setting up utility functions");
  bindings::setup_utilities(lua, w1_module);

  logger.dbg("setting up callback system");
  bindings::setup_callback_system(lua, w1_module);

  // NOTE: api analysis setup is deferred until after script is loaded
  // because it needs to register methods on the script's tracer table

  logger.dbg("setting up memory access");
  bindings::setup_memory_access(lua, w1_module);

  logger.dbg("setting up hooking functions");
  bindings::setup_hooking(lua, w1_module, hook_manager);

  logger.dbg("setting up signature scanning");
  bindings::setup_signature_scanning(lua, w1_module);

  logger.dbg("setting up calling convention");
  bindings::setup_calling_convention(lua, w1_module);

  logger.dbg("setting up symbol resolution");
  bindings::setup_symbol_resolution(lua, w1_module);

  logger.dbg("setting up output module");
  bindings::setup_output(lua, w1_module);

  logger.dbg("setting up gadget execution");
  bindings::setup_gadget_execution(lua, w1_module, gadget_executor);

  logger.dbg("setting up process dumping");
  bindings::setup_process_dumping(lua, w1_module);

  // register the w1 module with the lua state
  lua["w1"] = w1_module;

  logger.inf("all qbdi bindings registered successfully");
  logger.dbg(
      "available modules: core_types, register_access, vm_control, memory_access, memory_analysis, module_analysis, "
      "utilities, callback_system, api_analysis, hooking, signature_scanning, calling_convention, symbol_resolution, "
      "gadget_execution, process_dumping"
  );
}

} // namespace w1::tracers::script
