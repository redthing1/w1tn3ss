#pragma once

#include "runtime/lua_runtime.hpp"
#include "runtime/script_context.hpp"
#include "config/script_config.hpp"

#include "w1instrument/tracer/event.hpp"
#include "w1instrument/tracer/trace_context.hpp"

#include <QBDI.h>
#include <memory>
#include <redlog.hpp>

namespace w1::tracers::script {

class script_engine;

class script_tracer {
public:
  script_tracer();
  script_tracer(std::shared_ptr<script_engine> engine, script_config config);

  const char* name() const { return "w1script"; }
  static constexpr w1::event_mask requested_events() {
    using w1::event_kind;
    using w1::event_mask;

    event_mask mask = 0;
    mask = w1::event_mask_or(mask, w1::event_mask_of(event_kind::thread_start));
    mask = w1::event_mask_or(mask, w1::event_mask_of(event_kind::thread_stop));
    mask = w1::event_mask_or(mask, w1::event_mask_of(event_kind::vm_start));
    mask = w1::event_mask_or(mask, w1::event_mask_of(event_kind::vm_stop));
    mask = w1::event_mask_or(mask, w1::event_mask_of(event_kind::instruction_pre));
    mask = w1::event_mask_or(mask, w1::event_mask_of(event_kind::instruction_post));
    mask = w1::event_mask_or(mask, w1::event_mask_of(event_kind::basic_block_entry));
    mask = w1::event_mask_or(mask, w1::event_mask_of(event_kind::basic_block_exit));
    mask = w1::event_mask_or(mask, w1::event_mask_of(event_kind::exec_transfer_call));
    mask = w1::event_mask_or(mask, w1::event_mask_of(event_kind::exec_transfer_return));
    mask = w1::event_mask_or(mask, w1::event_mask_of(event_kind::memory_read));
    mask = w1::event_mask_or(mask, w1::event_mask_of(event_kind::memory_write));
    mask = w1::event_mask_or(mask, w1::event_mask_of(event_kind::memory_read_write));
    return mask;
  }

  QBDI::VMAction on_thread_start(w1::trace_context& ctx, const w1::thread_event& event);
  QBDI::VMAction on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event);

  QBDI::VMAction on_vm_start(
      w1::trace_context& ctx, const w1::sequence_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  QBDI::VMAction on_vm_stop(
      w1::trace_context& ctx, const w1::sequence_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );

  QBDI::VMAction on_instruction_pre(
      w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );
  QBDI::VMAction on_instruction_post(
      w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );

  QBDI::VMAction on_basic_block_entry(
      w1::trace_context& ctx, const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  QBDI::VMAction on_basic_block_exit(
      w1::trace_context& ctx, const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );

  QBDI::VMAction on_exec_transfer_call(
      w1::trace_context& ctx, const w1::exec_transfer_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  QBDI::VMAction on_exec_transfer_return(
      w1::trace_context& ctx, const w1::exec_transfer_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );

  QBDI::VMAction on_memory(
      w1::trace_context& ctx, const w1::memory_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );

private:
  bool ensure_initialized(w1::trace_context& ctx, const w1::thread_event* event);

  script_config config_{};
  redlog::logger logger_;
  bool initialized_ = false;
  bool failed_ = false;
  std::unique_ptr<runtime::script_context> context_;
  std::unique_ptr<runtime::lua_runtime> runtime_;
};

} // namespace w1::tracers::script
