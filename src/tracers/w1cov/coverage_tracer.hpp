#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>

#include <QBDI.h>

#include "w1instrument/tracer/event.hpp"
#include "w1instrument/tracer/trace_context.hpp"
#include "w1instrument/tracer/tracer.hpp"
#include "w1instrument/tracer/types.hpp"

#include "coverage_config.hpp"
#include "coverage_engine.hpp"

namespace w1cov {

enum class coverage_mode : uint8_t { basic_block, instruction };

template <coverage_mode mode> class coverage_tracer {
public:
  explicit coverage_tracer(std::shared_ptr<coverage_engine> engine);

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

  size_t get_coverage_unit_count() const;
  size_t get_module_count() const;
  uint64_t get_total_hits() const;

private:
  void record_coverage(uint64_t address, uint32_t size);

  std::shared_ptr<coverage_engine> engine_;
  coverage_engine::thread_writer writer_{};
};

} // namespace w1cov
