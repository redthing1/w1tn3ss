#include "api_analysis_processor.hpp"
#include "bindings/api_analysis.hpp"
#include <w1tn3ss/util/register_access.hpp>
#include <chrono>

namespace w1::tracers::script {

api_analysis_processor::api_analysis_processor() : logger_(redlog::get_logger("w1.api_processor")) {}

void api_analysis_processor::process_call(
    QBDI::VM* vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr,
    bindings::api_analysis_manager* api_manager, util::module_range_index* module_index,
    symbols::symbol_resolver* symbol_resolver
) {
  if (!api_manager || !module_index) {
    return;
  }

  // build api context
  w1::abi::api_context ctx;
  ctx.vm = vm;
  ctx.vm_state = state;
  ctx.gpr_state = gpr;
  ctx.fpr_state = fpr;
  ctx.module_index = module_index;
  ctx.timestamp = std::chrono::steady_clock::now().time_since_epoch().count();

  // for calls: source is where we're calling from, target is what we're calling
  ctx.call_address = state->sequenceStart;
  ctx.target_address = w1::registers::get_pc(gpr);

  // get module and symbol names
  if (auto module_info = module_index->find_containing(ctx.target_address)) {
    ctx.module_name = module_info->name;

    // resolve symbol if we have a resolver
    if (symbol_resolver) {
      if (auto sym_info = symbol_resolver->resolve_address(ctx.target_address, *module_index)) {
        ctx.symbol_name = sym_info->name;
      }
    }
  }

  logger_.dbg(
      "processing api call", redlog::field("target", ctx.target_address), redlog::field("module", ctx.module_name),
      redlog::field("symbol", ctx.symbol_name)
  );

  api_manager->process_call(ctx);
}

void api_analysis_processor::process_return(
    QBDI::VM* vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr,
    bindings::api_analysis_manager* api_manager, util::module_range_index* module_index,
    symbols::symbol_resolver* symbol_resolver
) {
  if (!api_manager || !module_index) {
    return;
  }

  // build api context
  w1::abi::api_context ctx;
  ctx.vm = vm;
  ctx.vm_state = state;
  ctx.gpr_state = gpr;
  ctx.fpr_state = fpr;
  ctx.module_index = module_index;
  ctx.timestamp = std::chrono::steady_clock::now().time_since_epoch().count();

  // for returns: source is what we're returning from, target is where we're returning to
  ctx.target_address = state->sequenceStart;
  ctx.call_address = w1::registers::get_pc(gpr);

  // get module and symbol names
  if (auto module_info = module_index->find_containing(ctx.target_address)) {
    ctx.module_name = module_info->name;

    // resolve symbol if we have a resolver
    if (symbol_resolver) {
      if (auto sym_info = symbol_resolver->resolve_address(ctx.target_address, *module_index)) {
        ctx.symbol_name = sym_info->name;
      }
    }
  }

  api_manager->process_return(ctx);
}

} // namespace w1::tracers::script