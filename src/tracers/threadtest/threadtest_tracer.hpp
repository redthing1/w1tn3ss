#pragma once

#include <cstdint>
#include <string>

#include <QBDI.h>
#include <redlog.hpp>

#include "w1tn3ss/tracer/event.hpp"
#include "w1tn3ss/tracer/trace_context.hpp"
#include "w1tn3ss/tracer/types.hpp"

#include "threadtest_config.hpp"

namespace threadtest {

class threadtest_tracer {
public:
  explicit threadtest_tracer(threadtest_config config);

  const char* name() const { return "threadtest"; }
  static constexpr w1::event_mask requested_events() {
    using w1::event_kind;
    w1::event_mask mask = 0;
    mask = w1::event_mask_or(mask, w1::event_mask_of(event_kind::basic_block_entry));
    mask = w1::event_mask_or(mask, w1::event_mask_of(event_kind::thread_start));
    mask = w1::event_mask_or(mask, w1::event_mask_of(event_kind::thread_stop));
    return mask;
  }

  void on_thread_start(w1::trace_context& ctx, const w1::thread_event& event);
  void on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event);

  QBDI::VMAction on_basic_block_entry(
      w1::trace_context& ctx, const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );

private:
  threadtest_config config_;
  redlog::logger log_ = redlog::get_logger("threadtest.tracer");
  uint64_t basic_blocks_ = 0;
  std::string thread_name_;
};

} // namespace threadtest
