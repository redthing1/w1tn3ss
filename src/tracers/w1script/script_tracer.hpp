#pragma once

#include "script_config.hpp"
#include "callback_manager.hpp"
#include "api_analysis_processor.hpp"
#include <w1tn3ss/engine/tracer_engine.hpp>

#include <sol/sol.hpp>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <string>
#include <memory>
#include <w1tn3ss/util/module_range_index.hpp>
#include <redlog.hpp>

namespace w1 {
namespace symbols {
class symbol_resolver;
}
namespace hooking {
class hook_manager;
}
} // namespace w1

namespace w1tn3ss::gadget {
class gadget_executor;
}

namespace w1::tracers::script {

// forward declarations
namespace bindings {
class api_analysis_manager;
}

class script_tracer {
private:
  config cfg_;
  redlog::logger logger_;

  sol::state lua_;
  sol::table script_table_;

  // callback management
  std::unique_ptr<callback_manager> callback_manager_;

  // api analysis manager
  std::shared_ptr<bindings::api_analysis_manager> api_manager_;

  // module index for api analysis
  std::unique_ptr<w1::util::module_range_index> module_index_;

  // symbol resolver for api analysis
  std::unique_ptr<w1::symbols::symbol_resolver> symbol_resolver_;

  // hook manager for dynamic hooking
  std::shared_ptr<w1::hooking::hook_manager> hook_manager_;

  // gadget executor for script-controlled gadget execution
  std::shared_ptr<w1tn3ss::gadget::gadget_executor> gadget_executor_;

  // api analysis processor
  std::unique_ptr<api_analysis_processor> api_processor_;

public:
  script_tracer();                           // defined in cpp due to unique_ptr of incomplete type
  explicit script_tracer(const config& cfg); // constructor with config
  ~script_tracer();                          // defined in cpp due to unique_ptr of incomplete type

  bool initialize(w1::tracer_engine<script_tracer>& engine);
  void shutdown();
  const char* get_name() const { return "w1script"; }

  // we intentionally don't define any on_* callback methods
  // to prevent tracer_engine from registering callbacks via SFINAE
  // all callbacks are registered manually by callback_manager

  // exception: on_vm_start is called explicitly by preload before vm->run
  // returns VMAction to control whether to continue or stop execution
  QBDI::VMAction on_vm_start(QBDI::VMInstanceRef vm);

  // api manager access (for exec_transfer callbacks)
  std::shared_ptr<bindings::api_analysis_manager> get_api_manager() { return api_manager_; }
};

} // namespace w1::tracers::script