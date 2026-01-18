#pragma once

#include <QBDI.h>
#include <redlog.hpp>

#include "w1instrument/tracer/event.hpp"
#include "w1instrument/tracer/trace_context.hpp"
#include "w1instrument/tracer/tracer.hpp"
#include "w1instrument/tracer/types.hpp"

#include "memory_collector.hpp"
#include "memory_config.hpp"

namespace w1mem {

class memory_tracer {
public:
  explicit memory_tracer(memory_config config);

  const char* name() const { return "w1mem"; }
  static constexpr w1::event_mask requested_events() {
    w1::event_mask mask = w1::event_mask_or(
        w1::event_mask_or(
            w1::event_mask_of(w1::event_kind::instruction_post), w1::event_mask_of(w1::event_kind::memory_read)
        ),
        w1::event_mask_of(w1::event_kind::thread_stop)
    );
    mask = w1::event_mask_or(mask, w1::event_mask_of(w1::event_kind::thread_start));
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

  const memory_stats& get_stats() const { return collector_.get_stats(); }

private:
  memory_config config_{};
  memory_collector collector_;
  redlog::logger log_ = redlog::get_logger("w1mem.tracer");
  bool initialized_ = false;
};

} // namespace w1mem
