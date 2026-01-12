#include "memory_tracer.hpp"

#include <utility>

namespace w1mem {

memory_tracer::memory_tracer(memory_config config)
    : config_(std::move(config)), collector_(config_), log_(redlog::get_logger("w1mem.tracer")) {
  if (config_.verbose > 0) {
    log_.inf("memory tracer created", redlog::field("output", config_.output_path));
  }
}

void memory_tracer::on_thread_start(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  (void) event;
  if (initialized_) {
    return;
  }

  log_.inf("initializing memory tracer");
  log_.inf(
      "memory tracer initialized", redlog::field("memory_recording", true),
      redlog::field("record_values", config_.record_values)
  );
  initialized_ = true;
}

void memory_tracer::on_instruction_post(
    w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  (void) ctx;
  (void) event;
  (void) vm;
  (void) gpr;
  (void) fpr;
  collector_.record_instruction();
}

void memory_tracer::on_memory(
    w1::trace_context& ctx, const w1::memory_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  (void) vm;
  (void) gpr;
  (void) fpr;

  uint64_t value = 0;
  bool value_valid = false;
  if (config_.record_values && event.value_valid) {
    value = event.value;
    value_valid = true;
  }

  if (event.is_read) {
    collector_.record_memory_access(
        ctx.modules(), event.instruction_address, event.address, event.size, /*access_type=*/1, value, value_valid
    );
  }

  if (event.is_write) {
    collector_.record_memory_access(
        ctx.modules(), event.instruction_address, event.address, event.size, /*access_type=*/2, value, value_valid
    );
  }
}

void memory_tracer::on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  (void) event;
  log_.inf("shutting down memory tracer");
}

} // namespace w1mem
