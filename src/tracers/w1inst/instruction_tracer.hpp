#pragma once

#include <string_view>

#include <QBDI.h>
#include <redlog.hpp>

#include "w1instrument/tracer/event.hpp"
#include "w1instrument/tracer/trace_context.hpp"
#include "w1instrument/tracer/tracer.hpp"
#include "w1instrument/tracer/types.hpp"

#include "instruction_collector.hpp"
#include "instruction_config.hpp"

namespace w1inst {

class instruction_tracer {
public:
  explicit instruction_tracer(instruction_config config);

  const char* name() const { return "w1inst"; }
  static constexpr w1::event_mask requested_events() {
    return w1::event_mask_or(
        w1::event_mask_of(w1::event_kind::instruction_pre),
        w1::event_mask_or(
            w1::event_mask_of(w1::event_kind::thread_start), w1::event_mask_of(w1::event_kind::thread_stop)
        )
    );
  }

  void on_thread_start(w1::trace_context& ctx, const w1::thread_event& event);

  void on_instruction_pre(
      w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );
  void on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event);

  // statistics access
  const mnemonic_stats& get_stats() const;

private:
  bool is_target_mnemonic(std::string_view mnemonic) const;

  instruction_config config_;
  mnemonic_collector collector_;
  redlog::logger log_ = redlog::get_logger("w1inst.tracer");
  bool initialized_ = false;
};

} // namespace w1inst
