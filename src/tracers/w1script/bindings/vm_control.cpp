#include "vm_control.hpp"
#include <redlog.hpp>
#include <cstdio>

namespace w1::tracers::script::bindings {

void setup_vm_control(sol::state& lua, sol::table& w1_module) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up vm control and instruction analysis functions");

  // address formatting utility
  // formats a QBDI::rword address as a hex string with consistent width
  w1_module.set_function("format_address", [](QBDI::rword addr) -> std::string {
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "0x%016lx", static_cast<unsigned long>(addr));
    return std::string(buffer);
  });

  // get disassembly of the current instruction
  // returns the assembly language representation of the instruction being executed
  w1_module.set_function("get_disassembly", [](QBDI::VM* vm) -> std::string {
    const QBDI::InstAnalysis* analysis = vm->getInstAnalysis();
    if (analysis && analysis->disassembly) {
      return std::string(analysis->disassembly);
    }
    return "<unknown>";
  });

  // execution control methods

  // call a function with DBI using current VM state
  // returns true if at least one block was executed
  w1_module.set_function(
      "call",
      [](QBDI::VM* vm, sol::optional<QBDI::rword*> retval_ptr, QBDI::rword function,
         sol::optional<sol::table> args_table) -> bool {
        try {
          std::vector<QBDI::rword> args;
          if (args_table) {
            // convert Lua table to vector of rword arguments
            for (auto& pair : *args_table) {
              if (pair.second.is<QBDI::rword>()) {
                args.push_back(pair.second.as<QBDI::rword>());
              }
            }
          }
          QBDI::rword* retval = retval_ptr ? *retval_ptr : nullptr;
          return vm->call(retval, function, args);
        } catch (const std::exception& e) {
          auto log = redlog::get_logger("w1.script_bindings");
          log.err("error in call(): " + std::string(e.what()));
          return false;
        }
      }
  );

  logger.dbg("vm control functions setup complete");
}

} // namespace w1::tracers::script::bindings