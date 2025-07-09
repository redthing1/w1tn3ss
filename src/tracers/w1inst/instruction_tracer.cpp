#include "instruction_tracer.hpp"
#include <fstream>

namespace w1inst {

instruction_tracer::instruction_tracer(const instruction_config& config)
    : config_(config), collector_(config.output_file, config.mnemonic_list) {

  if (config_.verbose) {
    log_.inf(
        "mnemonic tracer created", redlog::field("output", config_.output_file),
        redlog::field("target_mnemonics", config_.target_mnemonics)
    );
  }
}

bool instruction_tracer::initialize(w1::tracer_engine<instruction_tracer>& engine) {
  log_.inf("initializing mnemonic tracer");

  QBDI::VM* vm = engine.get_vm();
  if (!vm) {
    log_.error("vm instance is null");
    return false;
  }

  if (config_.verbose) {
    log_.inf("mnemonic tracer initialized", redlog::field("target_count", config_.mnemonic_list.size()));

    for (const auto& mnemonic : config_.mnemonic_list) {
      log_.debug("targeting mnemonic", redlog::field("mnemonic", mnemonic));
    }
  }

  return true;
}

void instruction_tracer::shutdown() {
  log_.inf("shutting down mnemonic tracer");
  // no export needed - streaming output handles everything
}

QBDI::VMAction instruction_tracer::on_instruction_preinst(
    QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  // count this instruction
  collector_.record_instruction();

  // get instruction analysis
  const QBDI::InstAnalysis* analysis = vm->getInstAnalysis();
  if (!analysis) {
    return QBDI::VMAction::CONTINUE;
  }

  // record if mnemonic matches our targets
  std::string mnemonic(analysis->mnemonic);
  collector_.record_mnemonic(analysis->address, mnemonic, analysis->disassembly);

  return QBDI::VMAction::CONTINUE;
}

const mnemonic_stats& instruction_tracer::get_stats() const { return collector_.get_stats(); }

} // namespace w1inst