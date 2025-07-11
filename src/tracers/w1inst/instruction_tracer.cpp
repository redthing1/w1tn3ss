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

  // manually register mnemonic callbacks based on config
  if (config_.mnemonic_list.empty()) {
    // if no specific mnemonics targeted, register for all instructions
    log_.inf("registering callback for all instructions");
    uint32_t id = vm->addCodeCB(QBDI::PREINST, on_mnemonic_callback, this);
    if (id == QBDI::INVALID_EVENTID) {
      log_.error("failed to register instruction callback");
      return false;
    }
    log_.inf("registered instruction callback", redlog::field("id", id));
  } else {
    // register specific mnemonic callbacks
    for (const auto& mnemonic : config_.mnemonic_list) {
      log_.inf("registering mnemonic callback", redlog::field("mnemonic", mnemonic));
      uint32_t id = vm->addMnemonicCB(mnemonic.c_str(), QBDI::PREINST, on_mnemonic_callback, this);
      if (id == QBDI::INVALID_EVENTID) {
        log_.error("failed to register mnemonic callback", redlog::field("mnemonic", mnemonic));
        return false;
      }
      log_.inf("registered mnemonic callback", redlog::field("mnemonic", mnemonic), redlog::field("id", id));
    }
  }

  if (config_.verbose) {
    log_.inf("mnemonic tracer initialized", redlog::field("target_count", config_.mnemonic_list.size()));
  }

  return true;
}

void instruction_tracer::shutdown() {
  const auto& stats = collector_.get_stats();
  log_.inf(
      "instruction collection completed", redlog::field("matched", stats.matched_instructions),
      redlog::field("unique_sites", stats.unique_sites), redlog::field("targets", stats.target_mnemonics.size())
  );
}

QBDI::VMAction instruction_tracer::on_mnemonic_callback(
    QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data
) {
  auto* tracer = static_cast<instruction_tracer*>(data);

  // get instruction analysis
  const QBDI::InstAnalysis* analysis = vm->getInstAnalysis();
  if (!analysis) {
    return QBDI::VMAction::CONTINUE;
  }

  // record the mnemonic (we know it matches if we're here via addMnemonicCB)
  std::string mnemonic(analysis->mnemonic);
  tracer->collector_.record_mnemonic(analysis->address, mnemonic, analysis->disassembly);

  return QBDI::VMAction::CONTINUE;
}

const mnemonic_stats& instruction_tracer::get_stats() const { return collector_.get_stats(); }

void instruction_tracer::print_statistics() const {
  const auto& stats = collector_.get_stats();
  log_.inf(
      "instruction stats", redlog::field("matched", stats.matched_instructions),
      redlog::field("unique_sites", stats.unique_sites), redlog::field("targets", stats.target_mnemonics.size())
  );
}

} // namespace w1inst