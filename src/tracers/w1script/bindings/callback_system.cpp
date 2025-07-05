#include "callback_system.hpp"
#include <redlog.hpp>
#include <stdexcept>

namespace w1::tracers::script::bindings {

// Global callback manager instance
std::shared_ptr<LuaCallbackManager> g_callback_manager;

// Helper function implementations

uint32_t getNextCallbackId(LuaCallbackManager* mgr) { return mgr->next_callback_id_++; }

QBDI::VM* get_vm_instance(void* vm_ptr) { return static_cast<QBDI::VM*>(vm_ptr); }

// LuaCallbackManager implementation

void LuaCallbackManager::registerInstCallback(uint32_t qbdi_id, uint32_t callback_id, sol::protected_function func) {
  inst_callbacks_[callback_id] = std::make_unique<LuaInstCallback>(std::move(func), shared_from_this(), callback_id);
  callback_id_to_qbdi_id_[callback_id] = qbdi_id;
}

void LuaCallbackManager::registerVMCallback(uint32_t qbdi_id, uint32_t callback_id, sol::protected_function func) {
  vm_callbacks_[callback_id] = std::make_unique<LuaVMCallback>(std::move(func), shared_from_this(), callback_id);
  callback_id_to_qbdi_id_[callback_id] = qbdi_id;
}

void LuaCallbackManager::registerInstrRuleCallback(
    uint32_t qbdi_id, uint32_t callback_id, sol::protected_function func
) {
  instr_rule_callbacks_[callback_id] =
      std::make_unique<LuaInstrRuleCallback>(std::move(func), shared_from_this(), callback_id);
  callback_id_to_qbdi_id_[callback_id] = qbdi_id;
}

void LuaCallbackManager::registerPersistentPtr(uint32_t callback_id, uint32_t* ptr) {
  callback_id_to_persistent_ptr_[callback_id] = ptr;
}

bool LuaCallbackManager::removeCallback(uint32_t callback_id) {
  bool found = false;

  auto inst_it = inst_callbacks_.find(callback_id);
  if (inst_it != inst_callbacks_.end()) {
    inst_callbacks_.erase(inst_it);
    found = true;
  }

  auto vm_it = vm_callbacks_.find(callback_id);
  if (vm_it != vm_callbacks_.end()) {
    vm_callbacks_.erase(vm_it);
    found = true;
  }

  auto rule_it = instr_rule_callbacks_.find(callback_id);
  if (rule_it != instr_rule_callbacks_.end()) {
    instr_rule_callbacks_.erase(rule_it);
    found = true;
  }

  auto id_it = callback_id_to_qbdi_id_.find(callback_id);
  if (id_it != callback_id_to_qbdi_id_.end()) {
    callback_id_to_qbdi_id_.erase(id_it);
  }

  // clean up persistent pointer
  auto ptr_it = callback_id_to_persistent_ptr_.find(callback_id);
  if (ptr_it != callback_id_to_persistent_ptr_.end()) {
    delete ptr_it->second;
    callback_id_to_persistent_ptr_.erase(ptr_it);
  }

  return found;
}

void LuaCallbackManager::removeAllCallbacks() {
  // clean up all persistent pointers
  for (auto& pair : callback_id_to_persistent_ptr_) {
    delete pair.second;
  }

  inst_callbacks_.clear();
  vm_callbacks_.clear();
  instr_rule_callbacks_.clear();
  callback_id_to_qbdi_id_.clear();
  callback_id_to_persistent_ptr_.clear();
}

LuaInstCallback* LuaCallbackManager::getInstCallback(uint32_t callback_id) {
  auto it = inst_callbacks_.find(callback_id);
  return (it != inst_callbacks_.end()) ? it->second.get() : nullptr;
}

LuaVMCallback* LuaCallbackManager::getVMCallback(uint32_t callback_id) {
  auto it = vm_callbacks_.find(callback_id);
  return (it != vm_callbacks_.end()) ? it->second.get() : nullptr;
}

LuaInstrRuleCallback* LuaCallbackManager::getInstrRuleCallback(uint32_t callback_id) {
  auto it = instr_rule_callbacks_.find(callback_id);
  return (it != instr_rule_callbacks_.end()) ? it->second.get() : nullptr;
}

// C++ callback wrappers that call into Lua

QBDI::VMAction luaInstCallbackWrapper(QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data) {
  auto log = redlog::get_logger("w1script.callbacks");

  if (!data) {
    log.err("null callback data in luaInstCallbackWrapper");
    return QBDI::VMAction::CONTINUE;
  }

  uint32_t* callback_id_ptr = static_cast<uint32_t*>(data);
  uint32_t callback_id = *callback_id_ptr;

  if (!g_callback_manager) {
    log.err("callback manager not initialized");
    return QBDI::VMAction::CONTINUE;
  }

  LuaInstCallback* callback = g_callback_manager->getInstCallback(callback_id);
  if (!callback) {
    log.err("callback not found", redlog::field("callback_id", callback_id));
    return QBDI::VMAction::CONTINUE;
  }

  try {
    auto result = callback->func(vm, gpr, fpr);
    if (result.valid()) {
      sol::optional<QBDI::VMAction> action = result;
      return action.value_or(QBDI::VMAction::CONTINUE);
    } else {
      sol::error err = result;
      log.err("Lua callback error", redlog::field("error", err.what()));
      return QBDI::VMAction::CONTINUE;
    }
  } catch (const std::exception& e) {
    log.err("exception in Lua instruction callback", redlog::field("error", e.what()));
    return QBDI::VMAction::CONTINUE;
  }
}

QBDI::VMAction luaVMCallbackWrapper(
    QBDI::VMInstanceRef vm, const QBDI::VMState* vmState, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data
) {
  auto log = redlog::get_logger("w1script.callbacks");

  if (!data) {
    log.err("null callback data in luaVMCallbackWrapper");
    return QBDI::VMAction::CONTINUE;
  }

  uint32_t* callback_id_ptr = static_cast<uint32_t*>(data);
  uint32_t callback_id = *callback_id_ptr;

  if (!g_callback_manager) {
    log.err("callback manager not initialized");
    return QBDI::VMAction::CONTINUE;
  }

  LuaVMCallback* callback = g_callback_manager->getVMCallback(callback_id);
  if (!callback) {
    log.err("VM callback not found", redlog::field("callback_id", callback_id));
    return QBDI::VMAction::CONTINUE;
  }

  try {
    auto result = callback->func(vm, vmState, gpr, fpr);
    if (result.valid()) {
      sol::optional<QBDI::VMAction> action = result;
      return action.value_or(QBDI::VMAction::CONTINUE);
    } else {
      sol::error err = result;
      log.err("Lua VM callback error", redlog::field("error", err.what()));
      return QBDI::VMAction::CONTINUE;
    }
  } catch (const std::exception& e) {
    log.err("exception in Lua VM callback", redlog::field("error", e.what()));
    return QBDI::VMAction::CONTINUE;
  }
}

std::vector<QBDI::InstrRuleDataCBK> luaInstrRuleCallbackWrapper(
    QBDI::VMInstanceRef vm, const QBDI::InstAnalysis* analysis, void* data
) {
  auto log = redlog::get_logger("w1script.callbacks");

  if (!data) {
    log.err("null callback data in luaInstrRuleCallbackWrapper");
    return {};
  }

  uint32_t* callback_id_ptr = static_cast<uint32_t*>(data);
  uint32_t callback_id = *callback_id_ptr;

  if (!g_callback_manager) {
    log.err("callback manager not initialized");
    return {};
  }

  LuaInstrRuleCallback* callback = g_callback_manager->getInstrRuleCallback(callback_id);
  if (!callback) {
    log.err("instrumentation rule callback not found", redlog::field("callback_id", callback_id));
    return {};
  }

  try {
    auto result = callback->func(vm, analysis);
    if (result.valid()) {
      // for now, return empty vector - instrumentation rules are complex
      // and would need proper handling of the returned data
      return {};
    } else {
      sol::error err = result;
      log.err("Lua instrumentation rule callback error", redlog::field("error", err.what()));
      return {};
    }
  } catch (const std::exception& e) {
    log.err("exception in Lua instrumentation rule callback", redlog::field("error", e.what()));
    return {};
  }
}

// Main setup function for callback system

void setup_callback_system(sol::state& lua, sol::table& w1_module) {
  auto log = redlog::get_logger("w1script.bindings.callback_system");
  log.dbg("setting up comprehensive callback registration system");

  // Initialize the callback manager
  if (!g_callback_manager) {
    g_callback_manager = std::make_shared<LuaCallbackManager>();
    log.inf("initialized Lua callback manager");
  }

  //------------- instruction callbacks -------------

  // addCodeCB - Universal instruction tracing
  w1_module.set_function(
      "addCodeCB",
      [](void* vm_ptr, int pos, sol::protected_function callback,
         sol::optional<int> priority_opt) -> sol::optional<uint32_t> {
        auto log = redlog::get_logger("w1script.callbacks");
        QBDI::VM* vm = get_vm_instance(vm_ptr);
        if (!vm) {
          return sol::nullopt;
        }

        if (!g_callback_manager) {
          log.err("callback manager not initialized");
          return sol::nullopt;
        }

        QBDI::InstPosition position = static_cast<QBDI::InstPosition>(pos);
        int priority = priority_opt.value_or(QBDI::PRIORITY_DEFAULT);

        try {
          uint32_t callback_id = getNextCallbackId(g_callback_manager.get());

          // create a persistent copy of the callback ID for the C callback data
          uint32_t* persistent_callback_id = new uint32_t(callback_id);

          uint32_t qbdi_id = vm->addCodeCB(position, luaInstCallbackWrapper, persistent_callback_id, priority);
          if (qbdi_id == QBDI::VMError::INVALID_EVENTID) {
            delete persistent_callback_id;
            log.err("failed to register instruction callback with QBDI");
            return sol::nullopt;
          }

          g_callback_manager->registerInstCallback(qbdi_id, callback_id, std::move(callback));
          g_callback_manager->registerPersistentPtr(callback_id, persistent_callback_id);
          log.dbg("registered addCodeCB", redlog::field("callback_id", callback_id), redlog::field("qbdi_id", qbdi_id));

          return callback_id;
        } catch (const std::exception& e) {
          log.err("exception in addCodeCB", redlog::field("error", e.what()));
          return sol::nullopt;
        }
      }
  );

  // addCodeAddrCB - Address-specific breakpoints
  w1_module.set_function(
      "addCodeAddrCB",
      [](void* vm_ptr, QBDI::rword address, int pos, sol::protected_function callback,
         sol::optional<int> priority_opt) -> sol::optional<uint32_t> {
        auto log = redlog::get_logger("w1script.callbacks");
        QBDI::VM* vm = get_vm_instance(vm_ptr);
        if (!vm) {
          return sol::nullopt;
        }

        if (!g_callback_manager) {
          log.err("callback manager not initialized");
          return sol::nullopt;
        }

        QBDI::InstPosition position = static_cast<QBDI::InstPosition>(pos);
        int priority = priority_opt.value_or(QBDI::PRIORITY_DEFAULT);

        try {
          uint32_t callback_id = getNextCallbackId(g_callback_manager.get());
          uint32_t* persistent_callback_id = new uint32_t(callback_id);

          uint32_t qbdi_id =
              vm->addCodeAddrCB(address, position, luaInstCallbackWrapper, persistent_callback_id, priority);
          if (qbdi_id == QBDI::VMError::INVALID_EVENTID) {
            delete persistent_callback_id;
            log.err("failed to register address-specific callback with QBDI");
            return sol::nullopt;
          }

          g_callback_manager->registerInstCallback(qbdi_id, callback_id, std::move(callback));
          g_callback_manager->registerPersistentPtr(callback_id, persistent_callback_id);
          log.dbg(
              "registered addCodeAddrCB", redlog::field("callback_id", callback_id), redlog::field("address", address)
          );

          return callback_id;
        } catch (const std::exception& e) {
          log.err("exception in addCodeAddrCB", redlog::field("error", e.what()));
          return sol::nullopt;
        }
      }
  );

  // addCodeRangeCB - Range-based callbacks
  w1_module.set_function(
      "addCodeRangeCB",
      [](void* vm_ptr, QBDI::rword start, QBDI::rword end, int pos, sol::protected_function callback,
         sol::optional<int> priority_opt) -> sol::optional<uint32_t> {
        auto log = redlog::get_logger("w1script.callbacks");
        QBDI::VM* vm = get_vm_instance(vm_ptr);
        if (!vm) {
          return sol::nullopt;
        }

        if (!g_callback_manager) {
          log.err("callback manager not initialized");
          return sol::nullopt;
        }

        QBDI::InstPosition position = static_cast<QBDI::InstPosition>(pos);
        int priority = priority_opt.value_or(QBDI::PRIORITY_DEFAULT);

        try {
          uint32_t callback_id = getNextCallbackId(g_callback_manager.get());
          uint32_t* persistent_callback_id = new uint32_t(callback_id);

          uint32_t qbdi_id =
              vm->addCodeRangeCB(start, end, position, luaInstCallbackWrapper, persistent_callback_id, priority);
          if (qbdi_id == QBDI::VMError::INVALID_EVENTID) {
            delete persistent_callback_id;
            log.err("failed to register range callback with QBDI");
            return sol::nullopt;
          }

          g_callback_manager->registerInstCallback(qbdi_id, callback_id, std::move(callback));
          g_callback_manager->registerPersistentPtr(callback_id, persistent_callback_id);
          log.dbg(
              "registered addCodeRangeCB", redlog::field("callback_id", callback_id), redlog::field("start", start),
              redlog::field("end", end)
          );

          return callback_id;
        } catch (const std::exception& e) {
          log.err("exception in addCodeRangeCB", redlog::field("error", e.what()));
          return sol::nullopt;
        }
      }
  );

  // addMnemonicCB - Instruction type callbacks
  w1_module.set_function(
      "addMnemonicCB",
      [](void* vm_ptr, const std::string& mnemonic, int pos, sol::protected_function callback,
         sol::optional<int> priority_opt) -> sol::optional<uint32_t> {
        auto log = redlog::get_logger("w1script.callbacks");
        QBDI::VM* vm = get_vm_instance(vm_ptr);
        if (!vm) {
          return sol::nullopt;
        }

        if (!g_callback_manager) {
          log.err("callback manager not initialized");
          return sol::nullopt;
        }

        QBDI::InstPosition position = static_cast<QBDI::InstPosition>(pos);
        int priority = priority_opt.value_or(QBDI::PRIORITY_DEFAULT);

        try {
          uint32_t callback_id = getNextCallbackId(g_callback_manager.get());
          uint32_t* persistent_callback_id = new uint32_t(callback_id);

          uint32_t qbdi_id =
              vm->addMnemonicCB(mnemonic.c_str(), position, luaInstCallbackWrapper, persistent_callback_id, priority);
          if (qbdi_id == QBDI::VMError::INVALID_EVENTID) {
            delete persistent_callback_id;
            log.err("failed to register mnemonic callback with QBDI", redlog::field("mnemonic", mnemonic));
            return sol::nullopt;
          }

          g_callback_manager->registerInstCallback(qbdi_id, callback_id, std::move(callback));
          g_callback_manager->registerPersistentPtr(callback_id, persistent_callback_id);
          log.dbg(
              "registered addMnemonicCB", redlog::field("callback_id", callback_id), redlog::field("mnemonic", mnemonic)
          );

          return callback_id;
        } catch (const std::exception& e) {
          log.err("exception in addMnemonicCB", redlog::field("error", e.what()));
          return sol::nullopt;
        }
      }
  );

  //------------- memory access callbacks -------------

  // addMemAccessCB - All memory access monitoring
  w1_module.set_function(
      "addMemAccessCB",
      [](void* vm_ptr, int type, sol::protected_function callback,
         sol::optional<int> priority_opt) -> sol::optional<uint32_t> {
        auto log = redlog::get_logger("w1script.callbacks");
        QBDI::VM* vm = get_vm_instance(vm_ptr);
        if (!vm) {
          return sol::nullopt;
        }

        if (!g_callback_manager) {
          log.err("callback manager not initialized");
          return sol::nullopt;
        }

        QBDI::MemoryAccessType access_type = static_cast<QBDI::MemoryAccessType>(type);
        int priority = priority_opt.value_or(QBDI::PRIORITY_DEFAULT);

        try {
          uint32_t callback_id = getNextCallbackId(g_callback_manager.get());
          uint32_t* persistent_callback_id = new uint32_t(callback_id);

          uint32_t qbdi_id = vm->addMemAccessCB(access_type, luaInstCallbackWrapper, persistent_callback_id, priority);
          if (qbdi_id == QBDI::VMError::INVALID_EVENTID) {
            delete persistent_callback_id;
            log.err("failed to register memory access callback with QBDI");
            return sol::nullopt;
          }

          g_callback_manager->registerInstCallback(qbdi_id, callback_id, std::move(callback));
          g_callback_manager->registerPersistentPtr(callback_id, persistent_callback_id);
          log.dbg("registered addMemAccessCB", redlog::field("callback_id", callback_id), redlog::field("type", type));

          return callback_id;
        } catch (const std::exception& e) {
          log.err("exception in addMemAccessCB", redlog::field("error", e.what()));
          return sol::nullopt;
        }
      }
  );

  // addMemAddrCB - Specific address watchpoints
  w1_module.set_function(
      "addMemAddrCB",
      [](void* vm_ptr, QBDI::rword address, int type, sol::protected_function callback) -> sol::optional<uint32_t> {
        auto log = redlog::get_logger("w1script.callbacks");
        QBDI::VM* vm = get_vm_instance(vm_ptr);
        if (!vm) {
          return sol::nullopt;
        }

        if (!g_callback_manager) {
          log.err("callback manager not initialized");
          return sol::nullopt;
        }

        QBDI::MemoryAccessType access_type = static_cast<QBDI::MemoryAccessType>(type);

        try {
          uint32_t callback_id = getNextCallbackId(g_callback_manager.get());
          uint32_t* persistent_callback_id = new uint32_t(callback_id);

          uint32_t qbdi_id = vm->addMemAddrCB(address, access_type, luaInstCallbackWrapper, persistent_callback_id);
          if (qbdi_id == QBDI::VMError::INVALID_EVENTID) {
            delete persistent_callback_id;
            log.err("failed to register memory address callback with QBDI");
            return sol::nullopt;
          }

          g_callback_manager->registerInstCallback(qbdi_id, callback_id, std::move(callback));
          g_callback_manager->registerPersistentPtr(callback_id, persistent_callback_id);
          log.dbg(
              "registered addMemAddrCB", redlog::field("callback_id", callback_id), redlog::field("address", address)
          );

          return callback_id;
        } catch (const std::exception& e) {
          log.err("exception in addMemAddrCB", redlog::field("error", e.what()));
          return sol::nullopt;
        }
      }
  );

  // addMemRangeCB - Memory range monitoring
  w1_module.set_function(
      "addMemRangeCB",
      [](void* vm_ptr, QBDI::rword start, QBDI::rword end, int type,
         sol::protected_function callback) -> sol::optional<uint32_t> {
        auto log = redlog::get_logger("w1script.callbacks");
        QBDI::VM* vm = get_vm_instance(vm_ptr);
        if (!vm) {
          return sol::nullopt;
        }

        if (!g_callback_manager) {
          log.err("callback manager not initialized");
          return sol::nullopt;
        }

        QBDI::MemoryAccessType access_type = static_cast<QBDI::MemoryAccessType>(type);

        try {
          uint32_t callback_id = getNextCallbackId(g_callback_manager.get());
          uint32_t* persistent_callback_id = new uint32_t(callback_id);

          uint32_t qbdi_id = vm->addMemRangeCB(start, end, access_type, luaInstCallbackWrapper, persistent_callback_id);
          if (qbdi_id == QBDI::VMError::INVALID_EVENTID) {
            delete persistent_callback_id;
            log.err("failed to register memory range callback with QBDI");
            return sol::nullopt;
          }

          g_callback_manager->registerInstCallback(qbdi_id, callback_id, std::move(callback));
          g_callback_manager->registerPersistentPtr(callback_id, persistent_callback_id);
          log.dbg(
              "registered addMemRangeCB", redlog::field("callback_id", callback_id), redlog::field("start", start),
              redlog::field("end", end)
          );

          return callback_id;
        } catch (const std::exception& e) {
          log.err("exception in addMemRangeCB", redlog::field("error", e.what()));
          return sol::nullopt;
        }
      }
  );

  //------------- vm event callbacks -------------

  // addVMEventCB - Control flow events
  w1_module.set_function(
      "addVMEventCB", [](void* vm_ptr, int mask, sol::protected_function callback) -> sol::optional<uint32_t> {
        auto log = redlog::get_logger("w1script.callbacks");
        QBDI::VM* vm = get_vm_instance(vm_ptr);
        if (!vm) {
          return sol::nullopt;
        }

        if (!g_callback_manager) {
          log.err("callback manager not initialized");
          return sol::nullopt;
        }

        QBDI::VMEvent event_mask = static_cast<QBDI::VMEvent>(mask);

        try {
          uint32_t callback_id = getNextCallbackId(g_callback_manager.get());
          uint32_t* persistent_callback_id = new uint32_t(callback_id);

          uint32_t qbdi_id = vm->addVMEventCB(event_mask, luaVMCallbackWrapper, persistent_callback_id);
          if (qbdi_id == QBDI::VMError::INVALID_EVENTID) {
            delete persistent_callback_id;
            log.err("failed to register VM event callback with QBDI");
            return sol::nullopt;
          }

          g_callback_manager->registerVMCallback(qbdi_id, callback_id, std::move(callback));
          g_callback_manager->registerPersistentPtr(callback_id, persistent_callback_id);
          log.dbg("registered addVMEventCB", redlog::field("callback_id", callback_id), redlog::field("mask", mask));

          return callback_id;
        } catch (const std::exception& e) {
          log.err("exception in addVMEventCB", redlog::field("error", e.what()));
          return sol::nullopt;
        }
      }
  );

  //------------- instrumentation rule callbacks -------------

  // addInstrRule - Custom instrumentation rules
  w1_module.set_function(
      "addInstrRule", [](void* vm_ptr, sol::protected_function callback, int analysis_type) -> sol::optional<uint32_t> {
        auto log = redlog::get_logger("w1script.callbacks");
        QBDI::VM* vm = get_vm_instance(vm_ptr);
        if (!vm) {
          return sol::nullopt;
        }

        if (!g_callback_manager) {
          log.err("callback manager not initialized");
          return sol::nullopt;
        }

        QBDI::AnalysisType type = static_cast<QBDI::AnalysisType>(analysis_type);

        try {
          uint32_t callback_id = getNextCallbackId(g_callback_manager.get());
          uint32_t* persistent_callback_id = new uint32_t(callback_id);

          uint32_t qbdi_id = vm->addInstrRule(luaInstrRuleCallbackWrapper, type, persistent_callback_id);
          if (qbdi_id == QBDI::VMError::INVALID_EVENTID) {
            delete persistent_callback_id;
            log.err("failed to register instrumentation rule callback with QBDI");
            return sol::nullopt;
          }

          g_callback_manager->registerInstrRuleCallback(qbdi_id, callback_id, std::move(callback));
          g_callback_manager->registerPersistentPtr(callback_id, persistent_callback_id);
          log.dbg(
              "registered addInstrRule", redlog::field("callback_id", callback_id),
              redlog::field("analysis_type", analysis_type)
          );

          return callback_id;
        } catch (const std::exception& e) {
          log.err("exception in addInstrRule", redlog::field("error", e.what()));
          return sol::nullopt;
        }
      }
  );

  //------------- callback management -------------

  // deleteInstrumentation - Remove specific callback
  w1_module.set_function("deleteInstrumentation", [](void* vm_ptr, uint32_t callback_id) -> bool {
    auto log = redlog::get_logger("w1script.callbacks");
    QBDI::VM* vm = get_vm_instance(vm_ptr);
    if (!vm) {
      return false;
    }

    if (!g_callback_manager) {
      log.err("callback manager not initialized");
      return false;
    }

    try {
      // find the QBDI ID for this callback
      auto it = g_callback_manager->callback_id_to_qbdi_id_.find(callback_id);
      if (it == g_callback_manager->callback_id_to_qbdi_id_.end()) {
        log.wrn("callback ID not found", redlog::field("callback_id", callback_id));
        return false;
      }

      uint32_t qbdi_id = it->second;
      bool success = vm->deleteInstrumentation(qbdi_id);

      if (success) {
        // memory cleanup is handled by removeCallback() which deletes the persistent pointer
        g_callback_manager->removeCallback(callback_id);
        log.dbg(
            "deleted instrumentation", redlog::field("callback_id", callback_id), redlog::field("qbdi_id", qbdi_id)
        );
      } else {
        log.err("failed to delete QBDI instrumentation", redlog::field("qbdi_id", qbdi_id));
      }

      return success;
    } catch (const std::exception& e) {
      log.err("exception in deleteInstrumentation", redlog::field("error", e.what()));
      return false;
    }
  });

  // deleteAllInstrumentations - Remove all callbacks
  w1_module.set_function("deleteAllInstrumentations", [](void* vm_ptr) -> bool {
    auto log = redlog::get_logger("w1script.callbacks");
    QBDI::VM* vm = get_vm_instance(vm_ptr);
    if (!vm) {
      return false;
    }

    if (!g_callback_manager) {
      log.err("callback manager not initialized");
      return false;
    }

    try {
      vm->deleteAllInstrumentations();
      g_callback_manager->removeAllCallbacks();
      log.inf("deleted all instrumentations");
      return true;
    } catch (const std::exception& e) {
      log.err("exception in deleteAllInstrumentations", redlog::field("error", e.what()));
      return false;
    }
  });

  //------------- callback introspection -------------

  // getActiveCallbackCount - Get count of active callbacks
  w1_module.set_function("getActiveCallbackCount", []() -> int {
    if (!g_callback_manager) {
      return 0;
    }
    return g_callback_manager->inst_callbacks_.size() + g_callback_manager->vm_callbacks_.size() +
           g_callback_manager->instr_rule_callbacks_.size();
  });

  // getCallbackInfo - Get information about active callbacks
  w1_module.set_function("getCallbackInfo", [&w1_module]() -> sol::table {
    sol::state_view lua(w1_module.lua_state());
    sol::table info = lua.create_table();

    if (!g_callback_manager) {
      info["instruction_callbacks"] = 0;
      info["vm_callbacks"] = 0;
      info["instr_rule_callbacks"] = 0;
      info["total"] = 0;
      return info;
    }

    info["instruction_callbacks"] = g_callback_manager->inst_callbacks_.size();
    info["vm_callbacks"] = g_callback_manager->vm_callbacks_.size();
    info["instr_rule_callbacks"] = g_callback_manager->instr_rule_callbacks_.size();
    info["total"] = g_callback_manager->inst_callbacks_.size() + g_callback_manager->vm_callbacks_.size() +
                    g_callback_manager->instr_rule_callbacks_.size();
    return info;
  });

  //------------- memory access utilities -------------

  // recordMemoryAccess - Enable automatic memory logging
  w1_module.set_function("recordMemoryAccess", [](void* vm_ptr, int type) -> bool {
    auto log = redlog::get_logger("w1script.callbacks");
    QBDI::VM* vm = get_vm_instance(vm_ptr);
    if (!vm) {
      return false;
    }

    QBDI::MemoryAccessType access_type = static_cast<QBDI::MemoryAccessType>(type);

    try {
      bool success = vm->recordMemoryAccess(access_type);
      if (success) {
        log.inf("memory recording enabled", redlog::field("type", type));
      } else {
        log.wrn("memory recording not supported or failed to enable");
      }
      return success;
    } catch (const std::exception& e) {
      log.err("exception in recordMemoryAccess", redlog::field("error", e.what()));
      return false;
    }
  });

  log.dbg("callback system setup complete");
}

} // namespace w1::tracers::script::bindings