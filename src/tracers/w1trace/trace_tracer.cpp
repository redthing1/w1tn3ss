#include "trace_tracer.hpp"

namespace w1trace {

trace_tracer::trace_tracer(const trace_config& config)
    : config_(config), collector_(config.output_file, config.buffer_size), log_(redlog::get_logger("w1trace.tracer")) {

  log_.inf(
      "trace tracer initialized", redlog::field("output_file", config_.output_file),
      redlog::field("buffer_size", config_.buffer_size)
  );
}

bool trace_tracer::initialize(w1::tracer_engine<trace_tracer>& engine) {
  log_.inf("initializing trace tracer");

  // No additional initialization needed - the tracer_engine will automatically
  // register our on_instruction_postinst callback via SFINAE detection

  log_.inf("trace tracer initialization complete");
  return true;
}

void trace_tracer::shutdown() {
  print_statistics();
  collector_.shutdown();
  log_.inf("trace collection completed");
}

QBDI::VMAction trace_tracer::on_instruction_postinst(QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) {
  // Get the current instruction address from analysis
  QBDI::VM* vm_ptr = static_cast<QBDI::VM*>(vm);
  const QBDI::InstAnalysis* analysis = vm_ptr->getInstAnalysis();
  uint64_t address = analysis ? analysis->address : 0;

  if (address != 0) {
    // Add to collector
    collector_.add_instruction_address(address);
  }

  // Continue execution
  return QBDI::VMAction::CONTINUE;
}

size_t trace_tracer::get_instruction_count() const { return collector_.get_instruction_count(); }

size_t trace_tracer::get_flush_count() const { return collector_.get_flush_count(); }

size_t trace_tracer::get_buffer_usage() const { return collector_.get_buffer_usage(); }

void trace_tracer::print_statistics() const {
  log_.inf(
      "trace stats", redlog::field("instructions", get_instruction_count()),
      redlog::field("flushes", get_flush_count()), redlog::field("buffer_usage", get_buffer_usage())
  );
}

const trace_collector& trace_tracer::get_collector() const { return collector_; }

trace_collector& trace_tracer::get_collector() { return collector_; }

} // namespace w1trace