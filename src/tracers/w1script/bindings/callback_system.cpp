#include "callback_system.hpp"
#include <redlog.hpp>
#include <stdexcept>

namespace w1::tracers::script::bindings {

// global callback manager instance
std::shared_ptr<LuaCallbackManager> g_callback_manager;

// helper function implementations

uint32_t getNextCallbackId(LuaCallbackManager* mgr) { return mgr->next_callback_id_++; }

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
  auto log = redlog::get_logger("w1.script_callbacks");

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
      log.err("lua callback error", redlog::field("error", err.what()));
      return QBDI::VMAction::CONTINUE;
    }
  } catch (const std::exception& e) {
    log.err("exception in lua instruction callback", redlog::field("error", e.what()));
    return QBDI::VMAction::CONTINUE;
  }
}

QBDI::VMAction luaVMCallbackWrapper(
    QBDI::VMInstanceRef vm, const QBDI::VMState* vmState, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data
) {
  auto log = redlog::get_logger("w1.script_callbacks");

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
  auto log = redlog::get_logger("w1.script_callbacks");

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

// main setup function for callback system

void setup_callback_system(sol::state& lua, sol::table& w1_module) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up comprehensive callback registration system");

  // Initialize the callback manager
  if (!g_callback_manager) {
    g_callback_manager = std::make_shared<LuaCallbackManager>();
    logger.inf("initialized Lua callback manager");
  }
}

} // namespace w1::tracers::script::bindings