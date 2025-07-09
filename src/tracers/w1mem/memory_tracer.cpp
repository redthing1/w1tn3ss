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
    log_.warn("memory recording not supported on this platform, using callback fallback");
  }

  log_.inf("memory tracer initialized", redlog::field("memory_recording", memory_recording_enabled_));
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
      uint8_t access_type = 0;
      if (access.type & QBDI::MEMORY_READ) {
        access_type = 1;
      } else if (access.type & QBDI::MEMORY_WRITE) {
        access_type = 2;
      }

      if (access_type > 0) {
        collector_.record_memory_access(instruction_addr, access.accessAddress, access.size, access_type);
      }
    }
  }

  return QBDI::VMAction::CONTINUE;
}

const memory_stats& memory_tracer::get_stats() const { return collector_.get_stats(); }

} // namespace w1mem