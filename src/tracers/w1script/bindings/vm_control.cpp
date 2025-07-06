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
  w1_module.set_function("get_disassembly", [](void* vm_ptr) -> std::string {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    const QBDI::InstAnalysis* analysis = vm->getInstAnalysis();
    if (analysis && analysis->disassembly) {
      return std::string(analysis->disassembly);
    }
    return "unknown";
  });

  // get the current instruction analysis
  // returns a pointer to the InstAnalysis structure for the current instruction
  // note: this returns lightuserdata that should be used with InstAnalysis usertype
  w1_module.set_function("get_inst_analysis", [](void* vm_ptr) -> const QBDI::InstAnalysis* {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    return vm->getInstAnalysis();
  });

  // get the current instruction address from analysis
  // alternative to reading from register state
  w1_module.set_function("get_inst_address", [](void* vm_ptr) -> QBDI::rword {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    const QBDI::InstAnalysis* analysis = vm->getInstAnalysis();
    if (analysis) {
      return analysis->address;
    }
    return 0;
  });

  // get the size of the current instruction
  w1_module.set_function("get_inst_size", [](void* vm_ptr) -> uint32_t {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    const QBDI::InstAnalysis* analysis = vm->getInstAnalysis();
    if (analysis) {
      return analysis->instSize;
    }
    return 0;
  });

  // check if current instruction affects control flow
  w1_module.set_function("inst_affects_control_flow", [](void* vm_ptr) -> bool {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    const QBDI::InstAnalysis* analysis = vm->getInstAnalysis();
    if (analysis) {
      return analysis->affectControlFlow;
    }
    return false;
  });

  // check if current instruction is a branch
  w1_module.set_function("inst_is_branch", [](void* vm_ptr) -> bool {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    const QBDI::InstAnalysis* analysis = vm->getInstAnalysis();
    if (analysis) {
      return analysis->isBranch;
    }
    return false;
  });

  // check if current instruction is a call
  w1_module.set_function("inst_is_call", [](void* vm_ptr) -> bool {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    const QBDI::InstAnalysis* analysis = vm->getInstAnalysis();
    if (analysis) {
      return analysis->isCall;
    }
    return false;
  });

  // check if current instruction is a return
  w1_module.set_function("inst_is_return", [](void* vm_ptr) -> bool {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    const QBDI::InstAnalysis* analysis = vm->getInstAnalysis();
    if (analysis) {
      return analysis->isReturn;
    }
    return false;
  });

  // check if current instruction may load from memory
  w1_module.set_function("inst_may_load", [](void* vm_ptr) -> bool {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    const QBDI::InstAnalysis* analysis = vm->getInstAnalysis();
    if (analysis) {
      return analysis->mayLoad;
    }
    return false;
  });

  // check if current instruction may store to memory
  w1_module.set_function("inst_may_store", [](void* vm_ptr) -> bool {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    const QBDI::InstAnalysis* analysis = vm->getInstAnalysis();
    if (analysis) {
      return analysis->mayStore;
    }
    return false;
  });

  // execution control methods

  // execute code from start to stop address
  // returns true if at least one block was executed
  w1_module.set_function("run", [](void* vm_ptr, QBDI::rword start, QBDI::rword stop) -> bool {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    try {
      return vm->run(start, stop);
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_bindings");
      log.err("error in run(): " + std::string(e.what()));
      return false;
    }
  });

  // call a function with DBI using current VM state
  // returns true if at least one block was executed
  w1_module.set_function(
      "call",
      [](void* vm_ptr, sol::optional<QBDI::rword*> retval_ptr, QBDI::rword function,
         sol::optional<sol::table> args_table) -> bool {
        QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
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

  // get current VM options
  w1_module.set_function("getOptions", [](void* vm_ptr) -> QBDI::Options {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    return vm->getOptions();
  });

  // set VM options (clears cache if options change)
  w1_module.set_function("setOptions", [](void* vm_ptr, QBDI::Options options) -> void {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    try {
      vm->setOptions(options);
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_bindings");
      log.err("error in setOptions(): " + std::string(e.what()));
    }
  });

  // instrumentation range management

  // add an address range to instrumented ranges
  w1_module.set_function("addInstrumentedRange", [](void* vm_ptr, QBDI::rword start, QBDI::rword end) -> void {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    try {
      vm->addInstrumentedRange(start, end);
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_bindings");
      log.err("error in addInstrumentedRange(): " + std::string(e.what()));
    }
  });

  // add a module by name to instrumented ranges
  // returns true if at least one range was added
  w1_module.set_function("addInstrumentedModule", [](void* vm_ptr, const std::string& name) -> bool {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    try {
      return vm->addInstrumentedModule(name);
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_bindings");
      log.err("error in addInstrumentedModule(): " + std::string(e.what()));
      return false;
    }
  });

  // add a module containing the given address to instrumented ranges
  // returns true if at least one range was added
  w1_module.set_function("addInstrumentedModuleFromAddr", [](void* vm_ptr, QBDI::rword addr) -> bool {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    try {
      return vm->addInstrumentedModuleFromAddr(addr);
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_bindings");
      log.err("error in addInstrumentedModuleFromAddr(): " + std::string(e.what()));
      return false;
    }
  });

  // remove an address range from instrumented ranges
  w1_module.set_function("removeInstrumentedRange", [](void* vm_ptr, QBDI::rword start, QBDI::rword end) -> void {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    try {
      vm->removeInstrumentedRange(start, end);
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_bindings");
      log.err("error in removeInstrumentedRange(): " + std::string(e.what()));
    }
  });

  // remove all instrumented ranges
  w1_module.set_function("removeAllInstrumentedRanges", [](void* vm_ptr) -> void {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    try {
      vm->removeAllInstrumentedRanges();
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_bindings");
      log.err("error in removeAllInstrumentedRanges(): " + std::string(e.what()));
    }
  });

  // state management

  // get current GPR state
  // returns pointer to GPRState structure - handle with care in Lua
  w1_module.set_function("getGPRState", [](void* vm_ptr) -> QBDI::GPRState* {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    return vm->getGPRState();
  });

  // set GPR state from pointer
  w1_module.set_function("setGPRState", [](void* vm_ptr, const QBDI::GPRState* state) -> void {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    try {
      vm->setGPRState(state);
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_bindings");
      log.err("error in setGPRState(): " + std::string(e.what()));
    }
  });

  // get current FPR state
  // returns pointer to FPRState structure - handle with care in Lua
  w1_module.set_function("getFPRState", [](void* vm_ptr) -> QBDI::FPRState* {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    return vm->getFPRState();
  });

  // set FPR state from pointer
  w1_module.set_function("setFPRState", [](void* vm_ptr, const QBDI::FPRState* state) -> void {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    try {
      vm->setFPRState(state);
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_bindings");
      log.err("error in setFPRState(): " + std::string(e.what()));
    }
  });

  // cache control

  // clear cache for specific address range
  w1_module.set_function("clearCache", [](void* vm_ptr, QBDI::rword start, QBDI::rword end) -> void {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    try {
      vm->clearCache(start, end);
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_bindings");
      log.err("error in clearCache(): " + std::string(e.what()));
    }
  });

  // clear entire translation cache
  w1_module.set_function("clearAllCache", [](void* vm_ptr) -> void {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    try {
      vm->clearAllCache();
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_bindings");
      log.err("error in clearAllCache(): " + std::string(e.what()));
    }
  });

  // pre-cache a basic block for optimization
  // returns true if block was cached successfully
  w1_module.set_function("precacheBasicBlock", [](void* vm_ptr, QBDI::rword pc) -> bool {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    try {
      return vm->precacheBasicBlock(pc);
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_bindings");
      log.err("error in precacheBasicBlock(): " + std::string(e.what()));
      return false;
    }
  });

  // memory layout functions

  // get current process memory maps
  // returns a Lua table with memory map information
  w1_module.set_function("getCurrentProcessMaps", [&lua]() -> sol::table {
    sol::state_view lua_view = lua.lua_state();
    sol::table result = lua_view.create_table();

    try {
      size_t size = 0;
      // note: using simplified implementation - full memory maps require platform-specific code
      sol::table result = lua_view.create_table();

      // simplified memory map - would need platform-specific implementation for full functionality
      auto log = redlog::get_logger("w1.script_bindings");
      log.wrn("getCurrentProcessMaps not fully implemented - returning empty table");
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_bindings");
      log.err("error in getCurrentProcessMaps(): " + std::string(e.what()));
    }

    return result;
  });

  // get list of loaded module names
  // returns a Lua table with module names
  w1_module.set_function("getModuleNames", [&lua]() -> sol::table {
    sol::state_view lua_view = lua.lua_state();
    sol::table result = lua_view.create_table();

    try {
      size_t size = 0;
      // note: using simplified implementation - full module enumeration requires platform-specific code
      sol::table result = lua_view.create_table();

      // simplified module names - would need platform-specific implementation for full functionality
      auto log = redlog::get_logger("w1.script_bindings");
      log.wrn("getModuleNames not fully implemented - returning empty table");
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_bindings");
      log.err("error in getModuleNames(): " + std::string(e.what()));
    }

    return result;
  });

  logger.dbg("vm control functions setup complete");
}

} // namespace w1::tracers::script::bindings