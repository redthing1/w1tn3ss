#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <QBDI.h>
#include <redlog.hpp>

#include "rewind_config.hpp"

#include "w1tn3ss/runtime/rewind/trace_sink.hpp"
#include "w1tn3ss/runtime/rewind/trace_types.hpp"
#include "w1tn3ss/runtime/rewind/trace_validator.hpp"
#include "w1tn3ss/tracer/event.hpp"
#include "w1tn3ss/tracer/trace_context.hpp"
#include "w1tn3ss/tracer/types.hpp"
#include "w1tn3ss/util/register_capture.hpp"

namespace w1rewind {

class rewind_tracer {
public:
  explicit rewind_tracer(rewind_config config, w1::rewind::trace_sink_ptr sink, w1::rewind::trace_validator_ptr validator);

  const char* name() const { return "w1rewind"; }
  static constexpr w1::event_mask requested_events() {
    w1::event_mask mask = w1::event_mask_or(
        w1::event_mask_of(w1::event_kind::instruction_post), w1::event_mask_of(w1::event_kind::thread_start)
    );
    mask = w1::event_mask_or(mask, w1::event_mask_of(w1::event_kind::thread_stop));
    mask = w1::event_mask_or(mask, w1::event_mask_of(w1::event_kind::memory_read));
    mask = w1::event_mask_or(mask, w1::event_mask_of(w1::event_kind::memory_write));
    return mask;
  }

  void on_thread_start(w1::trace_context& ctx, const w1::thread_event& event);
  void on_instruction_post(
      w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );
  void on_memory(
      w1::trace_context& ctx, const w1::memory_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );
  void on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event);

private:
  struct tracer_state {
    uint64_t sequence = 0;
    uint64_t instruction_count = 0;
    uint64_t boundary_counter = 0;
    uint64_t instructions_since_boundary = 0;
    bool stop_requested = false;
    bool validation_failed = false;
    std::optional<w1::util::register_state> last_register_state;
    std::optional<w1::rewind::trace_event> pending_instruction;
    std::optional<w1::rewind::trace_event> pending_boundary;
  };

  void reset_state();
  void flush_pending_event();
  void schedule_boundary_if_needed(uint64_t address, uint32_t size, const QBDI::GPRState* gpr);
  bool emit_event(const w1::rewind::trace_event& event);
  bool ensure_sink_ready();
  void capture_register_deltas(const QBDI::GPRState* gpr, w1::rewind::trace_event& event);
  void capture_full_registers(const QBDI::GPRState* gpr, w1::rewind::trace_event& event);
  void append_memory_delta(const w1::memory_event& event, std::vector<w1::rewind::trace_memory_delta>& out);
  void log_progress();

  rewind_config config_{};
  w1::rewind::trace_sink_ptr sink_;
  w1::rewind::trace_validator_ptr validator_;
  uint64_t thread_id_ = 0;
  std::string thread_name_;
  redlog::logger log_ = redlog::get_logger("w1rewind.tracer");

  bool initialized_ = false;
  tracer_state state_{};
};

} // namespace w1rewind
