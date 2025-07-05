#pragma once

#include "script_config.hpp"
#include <w1tn3ss/engine/tracer_engine.hpp>

#include <sol/sol.hpp>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <string>

namespace w1::tracers::script {

class script_tracer {
private:
  config cfg_;

  sol::state lua_;
  sol::table script_table_;
  std::unordered_set<std::string> enabled_callbacks_;

  // lua callback wrapper functions
  std::unordered_map<std::string, sol::function> lua_callbacks_;
  std::vector<uint32_t> registered_callback_ids_;

  bool load_script();
  void setup_callbacks();
  bool is_callback_enabled(const std::string& callback_name) const;
  void register_callbacks_dynamically(QBDI::VM* vm);
  QBDI::VMAction dispatch_simple_callback(
      const std::string& callback_name, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  QBDI::VMAction dispatch_vm_event_callback(
      const std::string& callback_name, QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );
  std::vector<QBDI::InstrRuleDataCBK> dispatch_instr_rule_callback(
      const std::string& callback_name, QBDI::VMInstanceRef vm, const QBDI::InstAnalysis* analysis, void* data
  );

public:
  script_tracer() = default;
  ~script_tracer() = default;

  bool initialize(w1::tracer_engine<script_tracer>& engine);
  void shutdown();
  const char* get_name() const { return "w1script"; }

  // no callback method definitions to prevent SFINAE detection
  // callbacks are registered dynamically based on script requirements
};

} // namespace w1::tracers::script