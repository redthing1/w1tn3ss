#include "memory_tracer.hpp"
#include <fstream>

namespace w1mem {

memory_tracer::memory_tracer(const memory_config& config)
    : config_(config), collector_(config.output_path), memory_recording_enabled_(false) {

  if (config_.verbose) {
    log_.inf("memory tracer created", redlog::field("output", config_.output_path));
  }
}

bool memory_tracer::initialize(w1::tracer_engine<memory_tracer>& engine) {
  log_.inf("initializing memory tracer");

  // enable qbdi memory recording for efficient collection
  QBDI::VM* vm = engine.get_vm();
  if (!vm) {
    log_.error("vm instance is null");
    return false;
  }

  // enable memory access recording
  memory_recording_enabled_ = vm->recordMemoryAccess(QBDI::MEMORY_READ_WRITE);
  if (!memory_recording_enabled_) {
    log_.err("recordMemoryAccess failed, unable to enable memory tracing");
    return false;
  }

  log_.inf(
      "memory tracer initialized", redlog::field("memory_recording", memory_recording_enabled_),
      redlog::field("record_values", config_.record_values)
  );
  return true;
}

void memory_tracer::shutdown() {
  log_.inf("shutting down memory tracer");
  // no export needed - streaming output handles everything
}

QBDI::VMAction memory_tracer::on_instruction_postinst(
    QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {

  // count this instruction
  collector_.record_instruction();

  if (memory_recording_enabled_) {
    // get memory accesses for this instruction
    std::vector<QBDI::MemoryAccess> accesses = vm->getInstMemoryAccess();

    // get instruction analysis for context
    const QBDI::InstAnalysis* analysis = vm->getInstAnalysis();
    uint64_t instruction_addr = analysis ? analysis->address : 0;

    // record each memory access
    for (const auto& access : accesses) {
      bool value_known = !(access.flags & QBDI::MEMORY_UNKNOWN_VALUE);
      uint64_t captured_value = (config_.record_values && value_known) ? access.value : 0;
      bool should_report_value = config_.record_values && value_known;

      if (access.type & QBDI::MEMORY_READ) {
        collector_.record_memory_access(
            instruction_addr, access.accessAddress, access.size, /*access_type=*/1, captured_value,
            should_report_value
        );
      }

      if (access.type & QBDI::MEMORY_WRITE) {
        collector_.record_memory_access(
            instruction_addr, access.accessAddress, access.size, /*access_type=*/2, captured_value,
            should_report_value
        );
      }
    }
  }

  return QBDI::VMAction::CONTINUE;
}

const memory_stats& memory_tracer::get_stats() const { return collector_.get_stats(); }

} // namespace w1mem
