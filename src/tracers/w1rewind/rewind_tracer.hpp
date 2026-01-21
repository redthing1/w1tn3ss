#pragma once

#include <memory>

#include <QBDI.h>

#include "rewind_config.hpp"
#include "rewind_recorder.hpp"

#include "w1rewind/trace/record_sink.hpp"
#include "w1instrument/tracer/event.hpp"
#include "w1instrument/tracer/trace_context.hpp"
#include "w1instrument/tracer/types.hpp"

namespace w1rewind {

class rewind_instruction_tracer {
public:
  explicit rewind_instruction_tracer(rewind_config config, std::shared_ptr<w1::rewind::trace_record_sink> sink);

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
  rewind_recorder recorder_;
};

class rewind_block_tracer {
public:
  explicit rewind_block_tracer(rewind_config config, std::shared_ptr<w1::rewind::trace_record_sink> sink);

  const char* name() const { return "w1rewind"; }
  static constexpr w1::event_mask requested_events() {
    w1::event_mask mask = w1::event_mask_or(
        w1::event_mask_of(w1::event_kind::basic_block_entry), w1::event_mask_of(w1::event_kind::thread_start)
    );
    mask = w1::event_mask_or(mask, w1::event_mask_of(w1::event_kind::thread_stop));
    return mask;
  }

  void on_thread_start(w1::trace_context& ctx, const w1::thread_event& event);
  void on_basic_block_entry(
      w1::trace_context& ctx, const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  void on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event);

private:
  rewind_recorder recorder_;
};

using rewind_tracer = rewind_instruction_tracer;

} // namespace w1rewind
