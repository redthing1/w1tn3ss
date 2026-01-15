#include "trace_tracer.hpp"

#include <utility>

namespace w1trace {

trace_tracer::trace_tracer(trace_config config)
    : config_(std::move(config)), collector_(config_), log_(redlog::get_logger("w1trace.tracer")) {
  log_.inf(
      "trace tracer initialized", redlog::field("output_file", config_.output_file),
      redlog::field("track_control_flow", config_.track_control_flow)
  );
}

void trace_tracer::on_thread_start(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  (void) event;
  if (initialized_) {
    return;
  }

  log_.inf("initializing trace tracer");
  log_.inf("trace tracer initialization complete");
  initialized_ = true;
}

void trace_tracer::on_instruction_pre(
    w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  (void) gpr;
  (void) fpr;

  const QBDI::InstAnalysis* analysis = vm ? vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION) : nullptr;
  uint64_t address = analysis ? analysis->address : event.address;

  if (config_.track_control_flow && pending_branch_) {
    branch_event branch{};
    branch.type = pending_branch_->type;
    branch.source = pending_branch_->source_address;
    branch.dest = address;
    collector_.record_branch(branch);
    pending_branch_.reset();
  }

  if (address != 0) {
    collector_.record_instruction(ctx.modules(), address);
  }

  if (config_.track_control_flow && analysis) {
    if (auto type = classify_branch_type(*analysis)) {
      pending_branch_ = pending_branch{address, std::move(*type)};
    }
  }
}

void trace_tracer::on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  (void) event;
  const auto& stats = collector_.get_stats();
  log_.inf(
      "trace stats", redlog::field("instructions", stats.total_instructions),
      redlog::field("branches", stats.total_branches), redlog::field("calls", stats.total_calls),
      redlog::field("returns", stats.total_returns)
  );
  collector_.shutdown();
  log_.inf("trace collection completed");
}

std::optional<std::string> trace_tracer::classify_branch_type(const QBDI::InstAnalysis& analysis) const {
  if (!analysis.affectControlFlow && !analysis.isCall && !analysis.isReturn && !analysis.isBranch) {
    return std::nullopt;
  }

  if (analysis.isCall) {
    return std::string{"call"};
  }
  if (analysis.isReturn) {
    return std::string{"ret"};
  }

  if (analysis.condition != QBDI::CONDITION_NONE && analysis.condition != QBDI::CONDITION_ALWAYS) {
    return std::string{"cond"};
  }

  return std::string{"jmp"};
}

} // namespace w1trace
