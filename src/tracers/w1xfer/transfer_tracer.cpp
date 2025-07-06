#include "transfer_tracer.hpp"

#include <fstream>

namespace w1xfer {

transfer_tracer::transfer_tracer(const transfer_config& config)
    : config_(config), collector_(
                           config.max_entries, config.log_registers, config.log_stack_info, config.log_call_targets,
                           config.analyze_apis, !config.output_file.empty()
                       ) {

  if (config_.verbose) {
    log_.inf(
        "transfer tracer created", redlog::field("output", config_.output_file),
        redlog::field("max_entries", config_.max_entries), redlog::field("log_registers", config_.log_registers),
        redlog::field("log_stack_info", config_.log_stack_info),
        redlog::field("log_call_targets", config_.log_call_targets), redlog::field("analyze_apis", config_.analyze_apis)
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

  // initialize module tracking for fast module name lookup
  if (config_.log_call_targets) {
    log_.inf("initializing module tracking");
    collector_.initialize_module_tracking();
    log_.inf("module tracking initialized");
  }

  if (config_.verbose) {
    log_.inf("transfer tracer initialized successfully");
  }

  return true;
}

void transfer_tracer::shutdown() {
  log_.inf("shutting down transfer tracer");
  export_report();
}

QBDI::VMAction transfer_tracer::on_exec_transfer_call(
    QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  // extract call information from vm state
  uint64_t source_addr = state->sequenceStart;

  // get target address from instruction pointer (architecture-specific)
  uint64_t target_addr = 0;
#if defined(QBDI_ARCH_X86_64)
  target_addr = gpr->rip;
#elif defined(QBDI_ARCH_AARCH64) || defined(QBDI_ARCH_ARM)
  target_addr = gpr->pc;
#elif defined(QBDI_ARCH_X86)
  target_addr = gpr->eip;
#endif

  if (config_.verbose) {
    std::string source_module = "unknown";
    std::string target_module = "unknown";

    if (config_.log_call_targets) {
      source_module = collector_.get_module_name(source_addr);
      target_module = collector_.get_module_name(target_addr);
    }

    log_.vrb(
        "call transfer detected", redlog::field("source", "0x%016llx", source_addr),
        redlog::field("target", "0x%016llx", target_addr), redlog::field("source_module", source_module),
        redlog::field("target_module", target_module)
    );
  }

  // record the call transfer
  collector_.record_call(source_addr, target_addr, vm, state, gpr, fpr);

  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction transfer_tracer::on_exec_transfer_return(
    QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  // extract return information from vm state
  uint64_t source_addr = state->sequenceStart;

  // get target address from instruction pointer (architecture-specific)
  uint64_t target_addr = 0;
#if defined(QBDI_ARCH_X86_64)
  target_addr = gpr->rip;
#elif defined(QBDI_ARCH_AARCH64) || defined(QBDI_ARCH_ARM)
  target_addr = gpr->pc;
#elif defined(QBDI_ARCH_X86)
  target_addr = gpr->eip;
#endif

  if (config_.verbose) {
    std::string source_module = "unknown";
    std::string target_module = "unknown";

    if (config_.log_call_targets) {
      source_module = collector_.get_module_name(source_addr);
      target_module = collector_.get_module_name(target_addr);
    }

    log_.vrb(
        "return transfer detected", redlog::field("source", "0x%016llx", source_addr),
        redlog::field("target", "0x%016llx", target_addr), redlog::field("source_module", source_module),
        redlog::field("target_module", target_module)
    );
  }

  // record the return transfer
  collector_.record_return(source_addr, target_addr, vm, state, gpr, fpr);

  return QBDI::VMAction::CONTINUE;
}

const transfer_stats& transfer_tracer::get_stats() const { return collector_.get_stats(); }

size_t transfer_tracer::get_trace_size() const { return collector_.get_trace_size(); }

void transfer_tracer::export_report() const {
  if (config_.output_file.empty()) {
    log_.inf("skipping export; no output file specified");
    return;
  }

  log_.inf("exporting transfer trace report", redlog::field("path", config_.output_file));

  try {
    w1xfer_report report = collector_.build_report();

    std::ofstream file(config_.output_file);
    if (!file.is_open()) {
      log_.err("failed to open output file", redlog::field("path", config_.output_file));
      return;
    }

    std::string json = JS::serializeStruct(report);
    file << json;
    file.close();

    log_.inf(
        "transfer trace report exported successfully", redlog::field("total_calls", report.stats.total_calls),
        redlog::field("total_returns", report.stats.total_returns),
        redlog::field("unique_call_targets", report.stats.unique_call_targets),
        redlog::field("max_call_depth", report.stats.max_call_depth),
        redlog::field("trace_entries", report.trace.size())
    );

  } catch (const std::exception& e) {
    log_.err("failed to export report", redlog::field("error", e.what()));
  }
}

} // namespace w1xfer