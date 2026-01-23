#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include <QBDI.h>
#include <redlog.hpp>

#include "config/rewind_config.hpp"
#include "engine/rewind_engine.hpp"
#include "thread/memory_filter.hpp"
#include "w1instrument/tracer/event.hpp"
#include "w1instrument/tracer/trace_context.hpp"
#include "w1instrument/tracer/types.hpp"
#include "w1runtime/register_capture.hpp"

namespace w1::runtime {
struct thread_info;
}

namespace w1rewind {

enum class rewind_flow { instruction, block };

template <rewind_flow Mode, bool CaptureMemory>
class rewind_thread_tracer {
public:
  explicit rewind_thread_tracer(std::shared_ptr<rewind_engine> engine, const rewind_config& config);
  rewind_thread_tracer(
      std::shared_ptr<rewind_engine> engine, const rewind_config& config, const w1::runtime::thread_info&
  );

  const char* name() const { return "w1rewind"; }

  static constexpr w1::event_mask requested_events() {
    using w1::event_kind;
    w1::event_mask mask = w1::event_mask_or(
        w1::event_mask_of(event_kind::thread_start), w1::event_mask_of(event_kind::thread_stop)
    );

    if constexpr (Mode == rewind_flow::instruction) {
      mask = w1::event_mask_or(mask, w1::event_mask_of(event_kind::instruction_post));
      if constexpr (CaptureMemory) {
        mask = w1::event_mask_or(mask, w1::event_mask_of(event_kind::memory_read));
        mask = w1::event_mask_or(mask, w1::event_mask_of(event_kind::memory_write));
      }
    } else {
      mask = w1::event_mask_or(mask, w1::event_mask_of(event_kind::basic_block_entry));
    }

    return mask;
  }

  void on_thread_start(w1::trace_context& ctx, const w1::thread_event& event);
  void on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event);

  void on_basic_block_entry(
      w1::trace_context& ctx, const w1::basic_block_event& event, QBDI::VMInstanceRef vm,
      const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  void on_instruction_post(
      w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );
  void on_memory(
      w1::trace_context& ctx, const w1::memory_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );

private:
  struct thread_state {
    uint64_t thread_id = 0;
    std::string name;
    uint64_t flow_count = 0;
    uint64_t memory_events = 0;
    snapshot_state snapshot_state{};
    std::optional<w1::util::register_state> last_registers;
    std::optional<pending_instruction> pending;
  };

  bool ensure_trace_ready(w1::trace_context& ctx, const std::optional<w1::util::register_state>& regs);
  bool should_capture_registers() const;
  bool uses_arm_flags() const;

  thread_state state_{};
  std::shared_ptr<rewind_engine> engine_{};
  rewind_config config_{};
  memory_filter memory_filter_;
  redlog::logger log_;
};

} // namespace w1rewind
