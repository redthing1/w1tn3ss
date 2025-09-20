#pragma once

#include <sol/sol.hpp>
#include <w1tn3ss/abi/api_listener.hpp>
#include <w1tn3ss/symbols/symbol_resolver.hpp>
#include <QBDI.h>
#include <redlog.hpp>
#include <memory>

namespace w1::tracers::script::bindings {

// forward declaration
class api_analysis_manager;

/**
 * @brief setup api analysis bindings for lua scripting
 *
 * This adds api monitoring capabilities to the w1script tracer:
 * - tracer:register_api_symbol_callback(module, symbol, callback)
 * - tracer:register_api_module_callback(module, callback)
 * - tracer:register_api_category_callback(category, callback)
 *
 * The callbacks receive rich api_event objects with:
 * - full api identification (module, symbol, category)
 * - extracted and interpreted arguments
 * - return values (for return events)
 * - formatted call strings
 *
 * @param lua the sol2 lua state
 * @param w1_module the w1 module table
 * @param tracer_table the tracer instance table
 * @param manager shared manager for API listener lifecycle
 */
void setup_api_analysis(
    sol::state& lua, sol::table& w1_module, sol::table& tracer_table, std::shared_ptr<api_analysis_manager>& manager
);

/**
 * @brief manages the lifecycle of api analysis for a script instance
 *
 * This class handles:
 * - lazy creation of api_listener
 * - registration of lua callbacks
 * - event conversion from c++ to lua
 * - cleanup on shutdown
 */
class api_analysis_manager : public std::enable_shared_from_this<api_analysis_manager> {
public:
  api_analysis_manager();
  ~api_analysis_manager();

  // initialize the api_listener with module index and symbol resolver
  // note: the module index and symbol resolver must outlive this manager instance
  void initialize(const util::module_range_index& index, symbols::symbol_resolver* resolver = nullptr);

  // ensure api_listener exists (lazy creation)
  void ensure_listener();

  // get the listener (may be null if not created)
  abi::api_listener* get_listener() { return listener_.get(); }

  // process exec_transfer events directly (absorbed from api_processor)
  void process_call(QBDI::VM* vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr);
  void process_return(QBDI::VM* vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr);

  // cleanup
  void shutdown();

private:
  std::unique_ptr<abi::api_listener> listener_;
  const util::module_range_index* module_index_ = nullptr;
  symbols::symbol_resolver* symbol_resolver_ = nullptr;
  bool initialized_ = false;
  redlog::logger logger_;
};

} // namespace w1::tracers::script::bindings