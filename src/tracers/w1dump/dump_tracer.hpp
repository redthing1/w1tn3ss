#pragma once

#include "dump_config.hpp"

#include "w1dump/memory_dumper.hpp"
#include "w1dump/process_dumper.hpp"
#include "w1instrument/tracer/event.hpp"
#include "w1instrument/tracer/trace_context.hpp"
#include "w1instrument/tracer/types.hpp"

#include <QBDI.h>
#include <redlog.hpp>

namespace w1dump {

class dump_tracer {
public:
  explicit dump_tracer(dump_config config);

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

  bool dump_completed() const { return dumped_; }

private:
  void perform_dump(w1::trace_context& ctx, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr);
  std::vector<w1::dump::dump_options::filter> parse_filters() const;

  dump_config config_{};
  redlog::logger log_ = redlog::get_logger("w1dump.tracer");
  bool dumped_ = false;
};

} // namespace w1dump
