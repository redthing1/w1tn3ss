#pragma once

#include <cstdint>
#include <memory>

#include <QBDI.h>
#include <redlog.hpp>

#include "w1gadget/gadget_executor.hpp"
#include "w1instrument/tracer/event.hpp"
#include "w1instrument/tracer/trace_context.hpp"
#include "w1instrument/tracer/types.hpp"

#include "gadgetdemo_config.hpp"

namespace gadgetdemo {

class gadgetdemo_tracer {
public:
  explicit gadgetdemo_tracer(gadgetdemo_config config);

  const char* name() const { return "gadgetdemo"; }
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

private:
  void ensure_executor(QBDI::VMInstanceRef vm);
  void resolve_main_base(const w1::runtime::module_registry& modules);
  void run_immediate_test();
  void run_demo();

  gadgetdemo_config config_;
  redlog::logger log_ = redlog::get_logger("gadgetdemo.tracer");
  std::unique_ptr<w1::gadget::gadget_executor> executor_;
  uint64_t instruction_count_ = 0;
  uint64_t main_base_ = 0;
  bool demo_completed_ = false;
  bool immediate_done_ = false;
};

} // namespace gadgetdemo
