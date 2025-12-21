#pragma once

#include <optional>
#include <string>

#include <QBDI.h>
#include <redlog.hpp>

#include "w1tn3ss/tracer/event.hpp"
#include "w1tn3ss/tracer/trace_context.hpp"
#include "w1tn3ss/tracer/tracer.hpp"
#include "w1tn3ss/tracer/types.hpp"

#include "trace_collector.hpp"
#include "trace_config.hpp"

namespace w1trace {

class trace_tracer {
public:
  explicit trace_tracer(trace_config config);

  const char* name() const { return "w1trace"; }
  static constexpr w1::event_mask requested_events() {
    return w1::event_mask_or(
        w1::event_mask_of(w1::event_kind::instruction_pre),
        w1::event_mask_or(w1::event_mask_of(w1::event_kind::thread_start),
                          w1::event_mask_of(w1::event_kind::thread_stop))
    );
  }

  void on_thread_start(w1::trace_context& ctx, const w1::thread_event& event);

  void on_instruction_pre(
      w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );
  void on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event);

  size_t get_instruction_count() const { return collector_.get_instruction_count(); }
  const trace_stats& get_stats() const { return collector_.get_stats(); }

private:
  struct pending_branch {
    uint64_t source_address = 0;
    std::string type;
  };

  std::optional<std::string> classify_branch_type(const QBDI::InstAnalysis& analysis) const;

  trace_config config_{};
  trace_collector collector_;
  redlog::logger log_;
  std::optional<pending_branch> pending_branch_{};
  bool initialized_ = false;
};

} // namespace w1trace
