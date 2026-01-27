#pragma once

#include <cstdint>
#include <memory>
#include <optional>

#include <QBDI.h>

#include "engine/dump_engine.hpp"
#include "w1instrument/tracer/event.hpp"
#include "w1instrument/tracer/trace_context.hpp"
#include "w1instrument/tracer/types.hpp"

namespace w1dump {

class dump_recorder {
public:
  explicit dump_recorder(std::shared_ptr<dump_engine> engine);

  const char* name() const { return "w1dump"; }
  static constexpr w1::event_mask requested_events() {
    using w1::event_kind;
    w1::event_mask mask = 0;
    mask = w1::event_mask_or(mask, w1::event_mask_of(event_kind::vm_start));
    mask = w1::event_mask_or(mask, w1::event_mask_of(event_kind::instruction_pre));
    return mask;
  }

  QBDI::VMAction on_vm_start(
      w1::trace_context& ctx, const w1::sequence_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );

  QBDI::VMAction on_instruction_pre(
      w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );

  bool dump_completed() const;

private:
  std::optional<uint64_t> resolve_module_trigger(w1::trace_context& ctx);
  bool should_dump_on_instruction(const w1::instruction_event& event, w1::trace_context& ctx);

  std::shared_ptr<dump_engine> engine_;
  std::optional<uint64_t> resolved_address_;
  uint64_t resolved_module_version_ = 0;
  bool logged_invalid_trigger_ = false;
  bool logged_missing_module_ = false;
};

} // namespace w1dump
