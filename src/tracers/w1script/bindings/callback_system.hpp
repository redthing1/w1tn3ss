/**
 * @file callback_system.hpp
 * @brief Comprehensive callback system bindings for w1script
 *
 * This module implements the bridge between QBDI's C++ callback system and Lua
 * functions, enabling powerful instrumentation capabilities. Supports instruction,
 * memory access, and VM event callbacks with proper parameter conversion.
 *
 * @author w1tn3ss Development Team
 * @date 2025
 */

#pragma once

#ifdef WITNESS_SCRIPT_ENABLED

#include <sol/sol.hpp>
#include <QBDI.h>
#include <memory>
#include <unordered_map>

namespace w1::tracers::script::bindings {

// Forward declarations
class LuaCallbackManager;

// Lua callback wrapper types
struct LuaInstCallback {
  sol::protected_function func;
  std::shared_ptr<LuaCallbackManager> manager;
  uint32_t callback_id;

  LuaInstCallback(sol::protected_function f, std::shared_ptr<LuaCallbackManager> mgr, uint32_t id)
      : func(std::move(f)), manager(mgr), callback_id(id) {}
};

struct LuaVMCallback {
  sol::protected_function func;
  std::shared_ptr<LuaCallbackManager> manager;
  uint32_t callback_id;

  LuaVMCallback(sol::protected_function f, std::shared_ptr<LuaCallbackManager> mgr, uint32_t id)
      : func(std::move(f)), manager(mgr), callback_id(id) {}
};

struct LuaInstrRuleCallback {
  sol::protected_function func;
  std::shared_ptr<LuaCallbackManager> manager;
  uint32_t callback_id;

  LuaInstrRuleCallback(sol::protected_function f, std::shared_ptr<LuaCallbackManager> mgr, uint32_t id)
      : func(std::move(f)), manager(mgr), callback_id(id) {}
};

// Callback manager class to handle Lua callback lifecycle
class LuaCallbackManager : public std::enable_shared_from_this<LuaCallbackManager> {
public:
  LuaCallbackManager() = default;
  ~LuaCallbackManager() {
    // Ensure all persistent pointers are cleaned up
    removeAllCallbacks();
  }

  // Store and manage callback references
  void registerInstCallback(uint32_t qbdi_id, uint32_t callback_id, sol::protected_function func);
  void registerVMCallback(uint32_t qbdi_id, uint32_t callback_id, sol::protected_function func);
  void registerInstrRuleCallback(uint32_t qbdi_id, uint32_t callback_id, sol::protected_function func);

  // Track persistent pointer for memory management
  void registerPersistentPtr(uint32_t callback_id, uint32_t* ptr);

  // Remove callbacks
  bool removeCallback(uint32_t callback_id);
  void removeAllCallbacks();

  // Get callback data
  LuaInstCallback* getInstCallback(uint32_t callback_id);
  LuaVMCallback* getVMCallback(uint32_t callback_id);
  LuaInstrRuleCallback* getInstrRuleCallback(uint32_t callback_id);

  // Public access to callback ID mapping for deletion operations
  std::unordered_map<uint32_t, uint32_t> callback_id_to_qbdi_id_; // our callback ID -> QBDI ID

  // Public access for introspection (debugging)
  std::unordered_map<uint32_t, std::unique_ptr<LuaInstCallback>> inst_callbacks_;
  std::unordered_map<uint32_t, std::unique_ptr<LuaVMCallback>> vm_callbacks_;
  std::unordered_map<uint32_t, std::unique_ptr<LuaInstrRuleCallback>> instr_rule_callbacks_;

private:
  uint32_t next_callback_id_ = 1;

  // Track persistent callback ID pointers for memory management
  std::unordered_map<uint32_t, uint32_t*> callback_id_to_persistent_ptr_;

  friend uint32_t getNextCallbackId(LuaCallbackManager* mgr);
};

// Helper functions
uint32_t getNextCallbackId(LuaCallbackManager* mgr);
QBDI::VM* get_vm_instance(void* vm_ptr);

// C++ callback wrappers that call into Lua
QBDI::VMAction luaInstCallbackWrapper(QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data);
QBDI::VMAction luaVMCallbackWrapper(
    QBDI::VMInstanceRef vm, const QBDI::VMState* vmState, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data
);
std::vector<QBDI::InstrRuleDataCBK> luaInstrRuleCallbackWrapper(
    QBDI::VMInstanceRef vm, const QBDI::InstAnalysis* analysis, void* data
);

// Global callback manager instance
extern std::shared_ptr<LuaCallbackManager> g_callback_manager;

/**
 * @brief Setup callback system functions for Lua bindings
 *
 * This module provides the comprehensive callback registration system for QBDI,
 * including:
 * - Instruction callbacks (addCodeCB, addCodeAddrCB, addCodeRangeCB, addMnemonicCB)
 * - Memory access callbacks (addMemAccessCB, addMemAddrCB, addMemRangeCB)
 * - VM event callbacks (addVMEventCB)
 * - Instrumentation rule callbacks (addInstrRule)
 * - Callback management (deleteInstrumentation, deleteAllInstrumentations)
 * - Memory recording control (recordMemoryAccess)
 *
 * All callback functions return optional uint32_t callback IDs that can be used
 * for callback management and removal.
 *
 * @param lua The Sol2 Lua state to register bindings with
 * @param w1_module The w1 module table to add bindings to
 */
void setup_callback_system(sol::state& lua, sol::table& w1_module);

} // namespace w1::tracers::script::bindings

#endif // WITNESS_SCRIPT_ENABLED