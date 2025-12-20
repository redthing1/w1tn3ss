#include "transfer_tracer.hpp"

#include <w1tn3ss/util/register_access.hpp>
#include <fstream>

namespace w1xfer {

transfer_tracer::transfer_tracer(const transfer_config& config) : config_(config), pipeline_(config) {

  if (config_.verbose) {
    log_.inf(
        "transfer tracer created", redlog::field("output", config_.output.path),
        redlog::field("capture_registers", config_.capture.registers),
        redlog::field("capture_stack", config_.capture.stack),
        redlog::field("enrich_modules", config_.enrich.modules),
        redlog::field("enrich_symbols", config_.enrich.symbols),
        redlog::field("analyze_apis", config_.enrich.analyze_apis)
    );
  }
}

bool transfer_tracer::initialize(w1::tracer_engine<transfer_tracer>& engine) {
  log_.inf("initializing transfer tracer");

  QBDI::VM* vm = engine.get_vm();
  if (!vm) {
    log_.err("vm instance is null");
    return false;
  }

  // initialize module tracking for features that depend on module metadata
  if (config_.enrich.modules || config_.enrich.symbols || config_.enrich.analyze_apis ||
      (config_.output.emit_metadata && !config_.output.path.empty())) {
    log_.inf("initializing module tracking");
    pipeline_.initialize_modules();
    log_.inf("module tracking initialized");
  }

  // output will stream automatically if output_file was provided

  if (config_.verbose) {
    log_.inf("transfer tracer initialized successfully");
  }

  return true;
}

void transfer_tracer::shutdown() {
  log_.inf("shutting down transfer tracer");

  // log summary stats
  const auto& stats = pipeline_.stats();
  log_.inf(
      "transfer collection completed", redlog::field("total_calls", stats.total_calls),
      redlog::field("total_returns", stats.total_returns), redlog::field("unique_targets", stats.unique_call_targets),
      redlog::field("max_depth", stats.max_call_depth)
  );
}

QBDI::VMAction transfer_tracer::on_exec_transfer_call(
    QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  // extract call information from vm state
  uint64_t source_addr = state->sequenceStart;

  // get target address from instruction pointer
  uint64_t target_addr = w1::registers::get_pc(gpr);

  if (config_.verbose) {
    log_.vrb(
        "call transfer detected", redlog::field("source", "0x%016llx", source_addr),
        redlog::field("target", "0x%016llx", target_addr)
    );
  }

  // record the call transfer
  pipeline_.record_call(source_addr, target_addr, vm, state, gpr, fpr);

  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction transfer_tracer::on_exec_transfer_return(
    QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  // extract return information from vm state
  uint64_t source_addr = state->sequenceStart;

  // get target address from instruction pointer
  uint64_t target_addr = w1::registers::get_pc(gpr);

  if (config_.verbose) {
    log_.vrb(
        "return transfer detected", redlog::field("source", "0x%016llx", source_addr),
        redlog::field("target", "0x%016llx", target_addr)
    );
  }

  // record the return transfer
  pipeline_.record_return(source_addr, target_addr, vm, state, gpr, fpr);

  return QBDI::VMAction::CONTINUE;
}

const transfer_stats& transfer_tracer::get_stats() const { return pipeline_.stats(); }

// removed get_trace_size and export_report - data now streams directly

} // namespace w1xfer
