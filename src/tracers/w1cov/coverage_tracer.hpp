#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>

#include <QBDI.h>
#include <redlog.hpp>

#include "w1instrument/tracer/event.hpp"
#include "w1instrument/tracer/trace_context.hpp"
#include "w1instrument/tracer/tracer.hpp"
#include "w1instrument/tracer/types.hpp"

#include "coverage_collector.hpp"
#include "coverage_config.hpp"
#include "coverage_module_tracker.hpp"

namespace w1cov {

enum class coverage_mode : uint8_t { basic_block, instruction };

template <coverage_mode mode> class coverage_tracer {
public:
  explicit coverage_tracer(coverage_config config);

  const char* name() const { return "w1cov"; }
  static constexpr w1::event_mask requested_events() {
    constexpr w1::event_mask base = w1::event_mask_or(
        w1::event_mask_of(w1::event_kind::thread_start), w1::event_mask_of(w1::event_kind::thread_stop)
    );
    if constexpr (mode == coverage_mode::instruction) {
      return w1::event_mask_or(base, w1::event_mask_of(w1::event_kind::instruction_pre));
    }
    return w1::event_mask_or(base, w1::event_mask_of(w1::event_kind::basic_block_entry));
  }

  void on_thread_start(w1::trace_context& ctx, const w1::thread_event& event);
  void on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event);

  void on_basic_block_entry(
      w1::trace_context& ctx, const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  void on_instruction_pre(
      w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );

  size_t get_coverage_unit_count() const { return collector_.get_coverage_unit_count(); }
  size_t get_module_count() const { return collector_.get_module_count(); }
  uint64_t get_total_hits() const { return collector_.get_total_hits(); }

  const coverage_collector& get_collector() const { return collector_; }

private:
  void record_coverage(w1::trace_context& ctx, uint64_t address, uint32_t size);
  void export_coverage();

  coverage_config config_{};
  coverage_collector collector_;
  coverage_module_tracker module_tracker_;
  redlog::logger log_ = redlog::get_logger("w1cov.tracer");
  bool initialized_ = false;
  bool exported_ = false;
};

} // namespace w1cov
