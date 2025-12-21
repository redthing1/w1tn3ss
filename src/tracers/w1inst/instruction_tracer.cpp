#include "instruction_tracer.hpp"

#include <utility>

namespace w1inst {

instruction_tracer::instruction_tracer(instruction_config config)
    : config_(std::move(config)), collector_(config_), log_(redlog::get_logger("w1inst.tracer")) {
  if (config_.verbose > 0) {
    log_.inf(
        "mnemonic tracer created", redlog::field("output", config_.output_file),
        redlog::field("target_mnemonics", config_.target_mnemonics)
    );
  }
}

void instruction_tracer::on_thread_start(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  (void) event;
  if (initialized_) {
    return;
  }

  log_.inf("initializing mnemonic tracer");
  if (config_.verbose > 0) {
    log_.inf("mnemonic tracer initialized", redlog::field("target_count", config_.mnemonic_list.size()));
  }
  initialized_ = true;
}

void instruction_tracer::on_instruction_pre(
    w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  (void) event;
  (void) gpr;
  (void) fpr;

  const QBDI::InstAnalysis* analysis =
      vm ? vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_DISASSEMBLY) : nullptr;
  if (!analysis) {
    return;
  }

  std::string_view mnemonic = analysis->mnemonic ? analysis->mnemonic : "";
  if (!is_target_mnemonic(mnemonic)) {
    return;
  }

  std::string_view disassembly = analysis->disassembly ? analysis->disassembly : "";
  uint64_t address = analysis->address ? analysis->address : event.address;
  collector_.record_mnemonic(ctx.modules(), address, mnemonic, disassembly);
}

void instruction_tracer::on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  const auto& stats = collector_.get_stats();
  log_.inf(
      "instruction collection completed", redlog::field("matched", stats.matched_instructions),
      redlog::field("unique_sites", stats.unique_sites), redlog::field("targets", stats.target_mnemonics.size())
  );
  collector_.shutdown();
}

const mnemonic_stats& instruction_tracer::get_stats() const { return collector_.get_stats(); }

bool instruction_tracer::is_target_mnemonic(std::string_view mnemonic) const {
  if (config_.mnemonic_list.empty()) {
    return true;
  }

  if (mnemonic.empty()) {
    return false;
  }

  for (const auto& target : config_.mnemonic_list) {
    if (mnemonic == target) {
      return true;
    }
  }

  return false;
}

} // namespace w1inst
