#pragma once

#include <sol/sol.hpp>
#include <QBDI.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <redlog.hpp>

namespace w1 {
namespace util {
class module_range_index;
}
namespace symbols {
class symbol_resolver;
}
} // namespace w1

namespace w1::tracers::script {

// forward declarations
namespace bindings {
class api_analysis_manager;
}

/**
 * manages callback registration and dispatch for script tracer
 * extracted from script_tracer to improve code organization
 */
class callback_manager {
public:
  // callback types enum to replace string-based lookup
  enum class callback_type {
    // vm lifecycle callbacks
    vm_start,

    // instruction callbacks
    instruction_preinst,
    instruction_postinst,

    // vm event callbacks
    sequence_entry,
    sequence_exit,
    basic_block_entry,
    basic_block_exit,
    basic_block_new,
    exec_transfer_call,
    exec_transfer_return,

    // memory access callbacks
    memory_read,
    memory_write,
    memory_read_write,

    // additional callback types
    code_addr,
    code_range,
    mnemonic,
    mem_addr,
    mem_range,
    instr_rule,
    instr_rule_range,
    instr_rule_range_set
  };

private:
  redlog::logger logger_;

  // enabled callbacks from script
  std::unordered_set<callback_type> enabled_callbacks_;

  // lua callback functions
  std::unordered_map<callback_type, sol::function> lua_callbacks_;

  // registered callback IDs from QBDI
  std::vector<uint32_t> registered_callback_ids_;

  // api analysis component (non-owning pointer)
  bindings::api_analysis_manager* api_manager_ = nullptr;

  // helper to convert string to callback type
  static std::optional<callback_type> string_to_callback_type(const std::string& name);

  // helper to get lua function name for callback type
  static std::string get_lua_function_name(callback_type type);

public:
  callback_manager();

  /**
   * setup callbacks from script table
   * @param script_table The loaded script table
   */
  void setup_callbacks(const sol::table& script_table);

  /**
   * register callbacks with QBDI VM based on script requirements
   * @param vm The QBDI VM instance
   */
  void register_callbacks(QBDI::VM* vm);

  /**
   * set api analysis manager for exec_transfer callbacks
   * @param api_manager The API analysis manager
   */
  void set_api_analysis_manager(bindings::api_analysis_manager* api_manager) { api_manager_ = api_manager; }

  /**
   * check if a callback is enabled
   * @param type The callback type
   * @return True if enabled
   */
  bool is_callback_enabled(callback_type type) const {
    return enabled_callbacks_.find(type) != enabled_callbacks_.end();
  }

  /**
   * get registered callback IDs for cleanup
   * @return Vector of callback IDs
   */
  const std::vector<uint32_t>& get_registered_ids() const { return registered_callback_ids_; }

  // dispatch methods for different callback types
  QBDI::VMAction dispatch_simple_callback(
      callback_type type, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );

  QBDI::VMAction dispatch_vm_start_callback(QBDI::VMInstanceRef vm);

  QBDI::VMAction dispatch_vm_event_callback(
      callback_type type, QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );

  std::vector<QBDI::InstrRuleDataCBK> dispatch_instr_rule_callback(
      callback_type type, QBDI::VMInstanceRef vm, const QBDI::InstAnalysis* analysis, void* data
  );
};

} // namespace w1::tracers::script