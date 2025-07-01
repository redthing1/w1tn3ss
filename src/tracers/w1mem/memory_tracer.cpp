#include "memory_tracer.hpp"
#include <fstream>

namespace w1mem {

memory_tracer::memory_tracer(const memory_config& config)
    : config_(config), collector_(config.max_trace_entries, config.collect_trace), memory_recording_enabled_(false) {

  if (config_.verbose) {
    log_.inf(
        "memory tracer created", redlog::field("output", config_.output_path),
        redlog::field("max_trace", config_.max_trace_entries), redlog::field("collect_trace", config_.collect_trace)
    );
  }
}

bool memory_tracer::initialize(w1::tracer_engine<memory_tracer>& engine) {
  log_.inf("initializing memory tracer");

  // enable QBDI memory recording for efficient collection
  QBDI::VM* vm = engine.get_vm();
  if (!vm) {
    log_.error("VM instance is null");
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
  export_report();
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

size_t memory_tracer::get_trace_size() const { return collector_.get_trace_size(); }

void memory_tracer::export_report() const {
  log_.inf("exporting memory trace report", redlog::field("path", config_.output_path));

  try {
    w1mem_report report = collector_.build_report();

    std::ofstream file(config_.output_path);
    if (!file.is_open()) {
      log_.error("failed to open output file", redlog::field("path", config_.output_path));
      return;
    }

    std::string json = JS::serializeStruct(report);
    file << json;
    file.close();

    log_.inf(
        "memory trace report exported successfully", redlog::field("instructions", report.stats.total_instructions),
        redlog::field("reads", report.stats.total_reads), redlog::field("writes", report.stats.total_writes),
        redlog::field("trace_entries", report.trace.size())
    );

  } catch (const std::exception& e) {
    log_.error("failed to export report", redlog::field("error", e.what()));
  }
}

} // namespace w1mem