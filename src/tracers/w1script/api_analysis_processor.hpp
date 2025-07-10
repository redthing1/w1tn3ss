#pragma once

#include <QBDI.h>
#include <memory>
#include <w1tn3ss/util/module_range_index.hpp>
#include <w1tn3ss/symbols/symbol_resolver.hpp>
#include <w1tn3ss/abi/api_listener.hpp>
#include <redlog.hpp>

namespace w1::tracers::script {

// forward declaration
namespace bindings {
class api_analysis_manager;
}

/**
 * handles api analysis processing for exec_transfer events
 * extracted from script_tracer to improve separation of concerns
 */
class api_analysis_processor {
private:
  redlog::logger logger_;

public:
  api_analysis_processor();

  /**
   * process exec_transfer_call event
   * @param vm QBDI VM instance
   * @param state VM state
   * @param gpr GPR state
   * @param fpr FPR state
   * @param api_manager API analysis manager
   * @param module_index Module index
   * @param symbol_resolver Symbol resolver (optional)
   */
  void process_call(
      QBDI::VM* vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr,
      bindings::api_analysis_manager* api_manager, util::module_range_index* module_index,
      symbols::symbol_resolver* symbol_resolver = nullptr
  );

  /**
   * process exec_transfer_return event
   * @param vm QBDI VM instance
   * @param state VM state
   * @param gpr GPR state
   * @param fpr FPR state
   * @param api_manager API analysis manager
   * @param module_index Module index
   * @param symbol_resolver Symbol resolver (optional)
   */
  void process_return(
      QBDI::VM* vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr,
      bindings::api_analysis_manager* api_manager, util::module_range_index* module_index,
      symbols::symbol_resolver* symbol_resolver = nullptr
  );
};

} // namespace w1::tracers::script