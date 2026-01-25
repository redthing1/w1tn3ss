#pragma once

#include <memory>

#include <QBDI.h>
#include <redlog.hpp>

#include "w1instrument/tracer/event.hpp"
#include "w1instrument/tracer/trace_context.hpp"
#include "w1instrument/tracer/tracer.hpp"
#include "w1instrument/tracer/types.hpp"

#include "config/transfer_config.hpp"
#include "engine/transfer_engine.hpp"

namespace w1::runtime {
struct thread_info;
}

namespace w1xfer {

class transfer_tracer {
public:
  transfer_tracer(
      std::shared_ptr<transfer_engine> engine, transfer_config config, const w1::runtime::thread_info& info
  );

  const char* name() const { return "w1xfer"; }
  static constexpr w1::event_mask requested_events() {
    return w1::event_mask_or(
        w1::event_mask_or(
            w1::event_mask_of(w1::event_kind::exec_transfer_call),
            w1::event_mask_of(w1::event_kind::exec_transfer_return)
        ),
        w1::event_mask_or(
            w1::event_mask_of(w1::event_kind::thread_start), w1::event_mask_of(w1::event_kind::thread_stop)
        )
    );
  }

  void on_thread_start(w1::trace_context& ctx, const w1::thread_event& event);
  void on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event);

  void on_exec_transfer_call(
      w1::trace_context& ctx, const w1::exec_transfer_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  void on_exec_transfer_return(
      w1::trace_context& ctx, const w1::exec_transfer_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );

private:
  std::shared_ptr<transfer_engine> engine_{};
  transfer_config config_{};
  transfer_engine::transfer_thread_state state_{};
  redlog::logger log_ = redlog::get_logger("w1xfer.thread");
  bool initialized_ = false;
};

} // namespace w1xfer
