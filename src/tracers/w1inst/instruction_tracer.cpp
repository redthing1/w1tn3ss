#include "instruction_tracer.hpp"
#include <fstream>

namespace w1inst {

instruction_tracer::instruction_tracer(const instruction_config& config)
    : config_(config), collector_(config.max_entries, config.mnemonic_list) {

  if (config_.verbose) {
    log_.inf(
        "mnemonic tracer created", redlog::field("output", config_.output_file),
        redlog::field("max_entries", config_.max_entries), redlog::field("target_mnemonics", config_.target_mnemonics)
    );
  }
}

bool instruction_tracer::initialize(w1::tracer_engine<instruction_tracer>& engine) {
  log_.inf("initializing mnemonic tracer");

  QBDI::VM* vm = engine.get_vm();
  if (!vm) {
    log_.error("VM instance is null");
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
  export_report();
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

size_t instruction_tracer::get_trace_size() const { return collector_.get_trace_size(); }

void instruction_tracer::export_report() const {
  log_.inf("exporting mnemonic trace report", redlog::field("path", config_.output_file));

  try {
    w1inst_report report = collector_.build_report();

    std::ofstream file(config_.output_file);
    if (!file.is_open()) {
      log_.error("failed to open output file", redlog::field("path", config_.output_file));
      return;
    }

    std::string json = JS::serializeStruct(report);
    file << json;
    file.close();

    log_.inf(
        "mnemonic trace report exported successfully",
        redlog::field("total_instructions", report.stats.total_instructions),
        redlog::field("matched_instructions", report.stats.matched_instructions),
        redlog::field("trace_entries", report.trace.size())
    );

  } catch (const std::exception& e) {
    log_.error("failed to export report", redlog::field("error", e.what()));
  }
}

} // namespace w1inst