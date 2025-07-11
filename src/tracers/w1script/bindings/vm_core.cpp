#include "vm_core.hpp"
#include <QBDI.h>
#include <redlog.hpp>

namespace w1::tracers::script::bindings {

// Singleton instance implementation
vm_callback_storage& vm_callback_storage::instance() {
  static vm_callback_storage instance;
  return instance;
}

size_t vm_callback_storage::store_callback(sol::protected_function callback) {
  std::lock_guard<std::mutex> lock(mutex_);
  callbacks_.push_back(std::move(callback));
  return callbacks_.size() - 1;
}

sol::protected_function* vm_callback_storage::get_callback(size_t idx) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (idx < callbacks_.size()) {
    return &callbacks_[idx];
  }
  return nullptr;
}

void vm_callback_storage::clear_all_callbacks() {
  std::lock_guard<std::mutex> lock(mutex_);
  callbacks_.clear();
}

void setup_vm_core(sol::state& lua, sol::table& w1_module) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up core VM bindings for direct VM access");

  // VMAction enum - control flow actions for callbacks
  w1_module.new_enum(
      "VMAction", "CONTINUE", QBDI::VMAction::CONTINUE, // Continue execution normally
      "SKIP_INST", QBDI::VMAction::SKIP_INST,           // Skip current instruction
      "SKIP_PATCH", QBDI::VMAction::SKIP_PATCH,         // Skip current patch
      "STOP", QBDI::VMAction::STOP                      // Stop execution
  );

  // For backward compatibility
  w1_module["CONTINUE"] = QBDI::VMAction::CONTINUE;
  w1_module["SKIP_INST"] = QBDI::VMAction::SKIP_INST;
  w1_module["SKIP_PATCH"] = QBDI::VMAction::SKIP_PATCH;
  w1_module["STOP"] = QBDI::VMAction::STOP;

  // Options enum - VM configuration options
  w1_module.new_enum(
      "Options", "NO_OPT", QBDI::Options::NO_OPT,                            // No options
      "OPT_DISABLE_FPR", QBDI::Options::OPT_DISABLE_FPR,                     // Disable FPR management
      "OPT_DISABLE_OPTIONAL_FPR", QBDI::Options::OPT_DISABLE_OPTIONAL_FPR,   // Disable optional FPR operations
      "OPT_DISABLE_LOCAL_MONITOR", QBDI::Options::OPT_DISABLE_LOCAL_MONITOR, // Disable local monitor
      "OPT_DISABLE_ERRNO_BACKUP", QBDI::Options::OPT_DISABLE_ERRNO_BACKUP,   // Disable errno backup
      "OPT_BYPASS_PAUTH", QBDI::Options::OPT_BYPASS_PAUTH,                   // Bypass pointer auth (ARM64)
      "OPT_ENABLE_BTI", QBDI::Options::OPT_ENABLE_BTI                        // Enable BTI on instrumented code
  );

  // Priority constants for callbacks
  w1_module["PRIORITY_DEFAULT"] = QBDI::PRIORITY_DEFAULT;

  // Error codes
  w1_module["INVALID_EVENTID"] = QBDI::VMError::INVALID_EVENTID;

  // Properly bind QBDI::VM as a usertype
  auto vm_type = lua.new_usertype<QBDI::VM>(
      "VM",
      // Cache management
      "clearCache", &QBDI::VM::clearCache, "clearAllCache", &QBDI::VM::clearAllCache, "getNbExecBlock",
      &QBDI::VM::getNbExecBlock, "reduceCacheTo", &QBDI::VM::reduceCacheTo, "precacheBasicBlock",
      &QBDI::VM::precacheBasicBlock,

      // State management
      "getGPRState", &QBDI::VM::getGPRState, "setGPRState", &QBDI::VM::setGPRState, "getFPRState",
      &QBDI::VM::getFPRState, "setFPRState", &QBDI::VM::setFPRState,

      // Options
      "getOptions", &QBDI::VM::getOptions, "setOptions", &QBDI::VM::setOptions,

      // Instrumentation ranges
      "addInstrumentedRange", &QBDI::VM::addInstrumentedRange, "addInstrumentedModule",
      &QBDI::VM::addInstrumentedModule, "addInstrumentedModuleFromAddr", &QBDI::VM::addInstrumentedModuleFromAddr,
      "instrumentAllExecutableMaps", &QBDI::VM::instrumentAllExecutableMaps, "removeInstrumentedRange",
      &QBDI::VM::removeInstrumentedRange, "removeInstrumentedModule", &QBDI::VM::removeInstrumentedModule,
      "removeInstrumentedModuleFromAddr", &QBDI::VM::removeInstrumentedModuleFromAddr, "removeAllInstrumentedRanges",
      &QBDI::VM::removeAllInstrumentedRanges,

      // Execution control
      "run", &QBDI::VM::run, "call",
      sol::overload(
          [](QBDI::VM* vm, QBDI::rword* retval, QBDI::rword function, const std::vector<QBDI::rword>& args) {
            return vm->call(retval, function, args);
          },
          [](QBDI::VM* vm, QBDI::rword* retval, QBDI::rword function) { return vm->call(retval, function); }
      ),

      // Analysis
      "getInstAnalysis",
      sol::overload(
          [](QBDI::VM* vm) {
            auto logger = redlog::get_logger("w1.script_vm");
            logger.trc("script calling vm:getInstAnalysis()");
            return vm->getInstAnalysis();
          },
          [](QBDI::VM* vm, QBDI::AnalysisType type) {
            auto logger = redlog::get_logger("w1.script_vm");
            logger.trc("script calling vm:getInstAnalysis(type)", redlog::field("type", static_cast<int>(type)));
            return vm->getInstAnalysis(type);
          }
      ),
      "getCachedInstAnalysis",
      sol::overload(
          [](QBDI::VM* vm, QBDI::rword addr) { return vm->getCachedInstAnalysis(addr); },
          [](QBDI::VM* vm, QBDI::rword addr, QBDI::AnalysisType type) { return vm->getCachedInstAnalysis(addr, type); }
      ),

      // Memory access
      "recordMemoryAccess", &QBDI::VM::recordMemoryAccess, "getInstMemoryAccess", &QBDI::VM::getInstMemoryAccess,
      "getBBMemoryAccess", &QBDI::VM::getBBMemoryAccess,

      // Callback registration
      "addCodeCB",
      sol::overload([](QBDI::VM* vm, QBDI::InstPosition pos, sol::protected_function callback) -> uint32_t {
        auto logger = redlog::get_logger("w1.script_vm");
        logger.trc(
            "script calling vm:addCodeCB", redlog::field("position", pos == QBDI::PREINST ? "PREINST" : "POSTINST")
        );

        size_t idx = vm_callback_storage::instance().store_callback(std::move(callback));

        uint32_t id = vm->addCodeCB(
            pos,
            [](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data) -> QBDI::VMAction {
              size_t idx = reinterpret_cast<size_t>(data);
              auto* callback = vm_callback_storage::instance().get_callback(idx);
              if (!callback) {
                return QBDI::VMAction::CONTINUE;
              }
              try {
                auto result = (*callback)(vm, gpr, fpr);
                if (result.valid() && result.get_type() == sol::type::number) {
                  return static_cast<QBDI::VMAction>(result.get<int>());
                }
              } catch (...) {
                // Callback failed, continue execution
              }
              return QBDI::VMAction::CONTINUE;
            },
            reinterpret_cast<void*>(idx)
        );

        logger.trc(
            "vm:addCodeCB returned", redlog::field("id", id), redlog::field("success", id != QBDI::INVALID_EVENTID)
        );
        return id;
      }),

      "addMnemonicCB",
      sol::overload(
          [](QBDI::VM* vm, const char* mnemonic, QBDI::InstPosition pos, sol::protected_function callback,
             sol::optional<int> priority) -> uint32_t {
            auto logger = redlog::get_logger("w1.script_vm");
            logger.trc(
                "script calling vm:addMnemonicCB", redlog::field("mnemonic", mnemonic),
                redlog::field("position", pos == QBDI::PREINST ? "PREINST" : "POSTINST"),
                redlog::field("priority", priority.value_or(QBDI::PRIORITY_DEFAULT))
            );

            size_t idx = vm_callback_storage::instance().store_callback(std::move(callback));

            uint32_t id = vm->addMnemonicCB(
                mnemonic, pos,
                [](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data) -> QBDI::VMAction {
                  size_t idx = reinterpret_cast<size_t>(data);
                  auto* callback = vm_callback_storage::instance().get_callback(idx);
                  if (!callback) {
                    return QBDI::VMAction::CONTINUE;
                  }
                  try {
                    auto result = (*callback)(vm, gpr, fpr);
                    if (result.valid() && result.get_type() == sol::type::number) {
                      return static_cast<QBDI::VMAction>(result.get<int>());
                    }
                  } catch (...) {
                    auto logger = redlog::get_logger("w1.script_vm");
                    logger.trc("mnemonic callback threw exception");
                  }
                  return QBDI::VMAction::CONTINUE;
                },
                reinterpret_cast<void*>(idx), priority.value_or(QBDI::PRIORITY_DEFAULT)
            );

            logger.trc(
                "vm:addMnemonicCB returned", redlog::field("id", id),
                redlog::field("success", id != QBDI::INVALID_EVENTID)
            );
            return id;
          }
      ),

      "addCodeAddrCB",
      sol::overload(
          [](QBDI::VM* vm, QBDI::rword address, QBDI::InstPosition pos, sol::protected_function callback,
             sol::optional<int> priority) -> uint32_t {
            size_t idx = vm_callback_storage::instance().store_callback(std::move(callback));

            return vm->addCodeAddrCB(
                address, pos,
                [](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data) -> QBDI::VMAction {
                  size_t idx = reinterpret_cast<size_t>(data);
                  auto* callback = vm_callback_storage::instance().get_callback(idx);
                  if (!callback) {
                    return QBDI::VMAction::CONTINUE;
                  }
                  try {
                    auto result = (*callback)(vm, gpr, fpr);
                    if (result.valid() && result.get_type() == sol::type::number) {
                      return static_cast<QBDI::VMAction>(result.get<int>());
                    }
                  } catch (...) {
                    // Callback failed, continue execution
                  }
                  return QBDI::VMAction::CONTINUE;
                },
                reinterpret_cast<void*>(idx), priority.value_or(QBDI::PRIORITY_DEFAULT)
            );
          }
      ),

      "addCodeRangeCB",
      sol::overload(
          [](QBDI::VM* vm, QBDI::rword start, QBDI::rword end, QBDI::InstPosition pos, sol::protected_function callback,
             sol::optional<int> priority) -> uint32_t {
            size_t idx = vm_callback_storage::instance().store_callback(std::move(callback));

            return vm->addCodeRangeCB(
                start, end, pos,
                [](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data) -> QBDI::VMAction {
                  size_t idx = reinterpret_cast<size_t>(data);
                  auto* callback = vm_callback_storage::instance().get_callback(idx);
                  if (!callback) {
                    return QBDI::VMAction::CONTINUE;
                  }
                  try {
                    auto result = (*callback)(vm, gpr, fpr);
                    if (result.valid() && result.get_type() == sol::type::number) {
                      return static_cast<QBDI::VMAction>(result.get<int>());
                    }
                  } catch (...) {
                    // Callback failed, continue execution
                  }
                  return QBDI::VMAction::CONTINUE;
                },
                reinterpret_cast<void*>(idx), priority.value_or(QBDI::PRIORITY_DEFAULT)
            );
          }
      ),

      "addMemAccessCB",
      sol::overload(
          [](QBDI::VM* vm, QBDI::MemoryAccessType type, sol::protected_function callback,
             sol::optional<int> priority) -> uint32_t {
            size_t idx = vm_callback_storage::instance().store_callback(std::move(callback));

            return vm->addMemAccessCB(
                type,
                [](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data) -> QBDI::VMAction {
                  size_t idx = reinterpret_cast<size_t>(data);
                  auto* callback = vm_callback_storage::instance().get_callback(idx);
                  if (!callback) {
                    return QBDI::VMAction::CONTINUE;
                  }
                  try {
                    auto result = (*callback)(vm, gpr, fpr);
                    if (result.valid() && result.get_type() == sol::type::number) {
                      return static_cast<QBDI::VMAction>(result.get<int>());
                    }
                  } catch (...) {
                    // Callback failed, continue execution
                  }
                  return QBDI::VMAction::CONTINUE;
                },
                reinterpret_cast<void*>(idx), priority.value_or(QBDI::PRIORITY_DEFAULT)
            );
          }
      ),

      "addVMEventCB", sol::overload([](QBDI::VM* vm, QBDI::VMEvent mask, sol::protected_function callback) -> uint32_t {
        size_t idx = vm_callback_storage::instance().store_callback(std::move(callback));

        return vm->addVMEventCB(
            mask,
            [](QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr,
               void* data) -> QBDI::VMAction {
              size_t idx = reinterpret_cast<size_t>(data);
              auto* callback = vm_callback_storage::instance().get_callback(idx);
              if (!callback) {
                return QBDI::VMAction::CONTINUE;
              }
              try {
                auto result = (*callback)(vm, state, gpr, fpr);
                if (result.valid() && result.get_type() == sol::type::number) {
                  return static_cast<QBDI::VMAction>(result.get<int>());
                }
              } catch (...) {
                // Callback failed, continue execution
              }
              return QBDI::VMAction::CONTINUE;
            },
            reinterpret_cast<void*>(idx)
        );
      }),

      "deleteInstrumentation",
      [](QBDI::VM* vm, uint32_t id) -> bool {
        auto logger = redlog::get_logger("w1.script_vm");
        logger.trc("script calling vm:deleteInstrumentation", redlog::field("id", id));
        bool result = vm->deleteInstrumentation(id);
        logger.trc("vm:deleteInstrumentation returned", redlog::field("success", result));
        return result;
      },
      "deleteAllInstrumentations",
      [](QBDI::VM* vm) -> void {
        auto logger = redlog::get_logger("w1.script_vm");
        logger.trc("script calling vm:deleteAllInstrumentations");
        vm->deleteAllInstrumentations();
      },

      // Errno backup
      "getErrno", &QBDI::VM::getErrno, "setErrno", &QBDI::VM::setErrno
  );

  // Register in the QBDI namespace for consistency
  if (!lua["QBDI"].valid()) {
    lua["QBDI"] = lua.create_table();
  }
  lua["QBDI"]["VM"] = vm_type;

  // Register cleanup function
  w1_module.set_function("_cleanup_vm_callbacks", []() { vm_callback_storage::instance().clear_all_callbacks(); });

  // Since we properly bound the VM type, we don't need void* wrapper functions anymore
  // Users can call methods directly on the VM object

  logger.dbg("core VM bindings setup complete");
}

} // namespace w1::tracers::script::bindings