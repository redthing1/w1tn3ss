#include "trace_tracer.hpp"

namespace w1trace {

trace_tracer::trace_tracer(const trace_config& config)
    : config_(config), collector_(config.output_file, config.track_control_flow),
      log_(redlog::get_logger("w1trace.tracer")) {

  log_.inf(
      "trace tracer initialized", redlog::field("output_file", config_.output_file),
      redlog::field("track_control_flow", config_.track_control_flow)
  );
}

bool trace_tracer::initialize(w1::tracer_engine<trace_tracer>& engine) {
  log_.inf("initializing trace tracer");

  // register control flow callbacks if enabled
  if (config_.track_control_flow) {
    QBDI::VM* vm = engine.get_vm();
    if (!vm) {
      log_.err("vm instance is null");
      return false;
    }

    if (!register_control_flow_callbacks(vm)) {
      log_.err("failed to register control flow callbacks");
      return false;
    }
  }

  // on_instruction_preinst callback is registered automatically via sfinae detection

  log_.inf("trace tracer initialization complete");
  return true;
}

bool trace_tracer::register_control_flow_callbacks(QBDI::VM* vm) {
  auto mnemonics = get_architecture_mnemonics();

  log_.inf("registering control flow callbacks", redlog::field("mnemonic_count", mnemonics.size()));

  for (const auto& mnemonic : mnemonics) {
    uint32_t id = vm->addMnemonicCB(mnemonic.c_str(), QBDI::PREINST, on_branch_mnemonic, this);
    if (id == QBDI::INVALID_EVENTID) {
      log_.err("failed to register mnemonic callback", redlog::field("mnemonic", mnemonic));
      return false;
    }
    callback_ids_.push_back(id);
    log_.dbg("registered mnemonic callback", redlog::field("mnemonic", mnemonic), redlog::field("id", id));
  }

  return true;
}

std::vector<std::string> trace_tracer::get_architecture_mnemonics() const {
  std::vector<std::string> mnemonics;

#if defined(QBDI_ARCH_AARCH64) || defined(QBDI_ARCH_ARM)
  // arm64/arm branch instructions
  mnemonics = {"B*", "BL*", "BR*", "BLR*", "RET*"};
#elif defined(QBDI_ARCH_X86_64) || defined(QBDI_ARCH_X86)
  // x86/x64 branch instructions
  mnemonics = {"CALL*", "JMP*", "RET*", "J*"};
#else
  log_.wrn("unsupported architecture for control flow tracking");
#endif

  return mnemonics;
}

void trace_tracer::shutdown() {
  print_statistics();
  collector_.shutdown();
  log_.inf("trace collection completed");
}

QBDI::VMAction trace_tracer::on_instruction_preinst(QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) {
  // get the current instruction address from analysis
  QBDI::VM* vm_ptr = static_cast<QBDI::VM*>(vm);
  const QBDI::InstAnalysis* analysis = vm_ptr->getInstAnalysis();
  uint64_t address = analysis ? analysis->address : 0;

  if (address != 0) {
    // record the instruction
    collector_.record_instruction(address);
  }

  // continue execution
  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction trace_tracer::on_branch_mnemonic(
    QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data
) {
  auto* tracer = static_cast<trace_tracer*>(data);

  // get instruction analysis
  const QBDI::InstAnalysis* analysis = vm->getInstAnalysis();
  if (!analysis) {
    return QBDI::VMAction::CONTINUE;
  }

  // mark pending branch
  tracer->collector_.mark_pending_branch(analysis->address, analysis->mnemonic);

  return QBDI::VMAction::CONTINUE;
}

size_t trace_tracer::get_instruction_count() const { return collector_.get_instruction_count(); }

const trace_stats& trace_tracer::get_stats() const { return collector_.get_stats(); }

void trace_tracer::print_statistics() const {
  const auto& stats = collector_.get_stats();
  log_.inf(
      "trace stats", redlog::field("instructions", stats.total_instructions),
      redlog::field("branches", stats.total_branches), redlog::field("calls", stats.total_calls),
      redlog::field("returns", stats.total_returns)
  );
}

const trace_collector& trace_tracer::get_collector() const { return collector_; }

trace_collector& trace_tracer::get_collector() { return collector_; }

} // namespace w1trace