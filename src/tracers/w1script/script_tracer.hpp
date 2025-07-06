#pragma once

#include "script_config.hpp"
#include <w1tn3ss/engine/tracer_engine.hpp>

#include <sol/sol.hpp>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <string>
#include <memory>
#include <w1tn3ss/util/module_range_index.hpp>

namespace w1 {
namespace lief {
class lief_symbol_resolver;
}
}

namespace w1::tracers::script {

// forward declarations
namespace bindings {
class api_analysis_manager;
}

class script_tracer {
private:
  config cfg_;

  sol::state lua_;
  sol::table script_table_;
  std::unordered_set<std::string> enabled_callbacks_;

  // lua callback wrapper functions
  std::unordered_map<std::string, sol::function> lua_callbacks_;
  std::vector<uint32_t> registered_callback_ids_;
  
  // api analysis manager
  std::shared_ptr<bindings::api_analysis_manager> api_manager_;
  
  // module index for api analysis
  std::unique_ptr<w1::util::module_range_index> module_index_;
  
  // symbol resolver for api analysis
  std::unique_ptr<w1::lief::lief_symbol_resolver> symbol_resolver_;

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
  script_tracer(); // defined in cpp due to unique_ptr of incomplete type
  ~script_tracer(); // defined in cpp due to unique_ptr of incomplete type

  bool initialize(w1::tracer_engine<script_tracer>& engine);
  void shutdown();
  const char* get_name() const { return "w1script"; }

  // no callback method definitions to prevent sfinae detection
  // callbacks are registered dynamically based on script requirements
  
  // api manager access (for exec_transfer callbacks)
  std::shared_ptr<bindings::api_analysis_manager> get_api_manager() { return api_manager_; }
};

} // namespace w1::tracers::script