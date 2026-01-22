#include "coverage_tracer.hpp"

#include <algorithm>

namespace w1cov {

template <coverage_mode mode>
coverage_tracer<mode>::coverage_tracer(std::shared_ptr<coverage_engine> engine)
    : engine_(std::move(engine)) {}

template <coverage_mode mode>
void coverage_tracer<mode>::on_thread_start(w1::trace_context& ctx, const w1::thread_event& event) {
  (void)ctx;
  (void)event;
  if (!engine_) {
    return;
  }
  writer_ = engine_->begin_thread();
}

template <coverage_mode mode>
void coverage_tracer<mode>::on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event) {
  (void)ctx;
  (void)event;
  if (!engine_) {
    return;
  }
  writer_.flush();
  writer_ = {};
}

template <coverage_mode mode>
void coverage_tracer<mode>::on_basic_block_entry(
    w1::trace_context& ctx, const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  (void) vm;
  (void) state;
  (void) gpr;
  (void) fpr;
  (void) ctx;

  if constexpr (mode == coverage_mode::basic_block) {
    if (event.address == 0 || event.size == 0) {
      return;
    }

    uint32_t size = std::min<uint32_t>(event.size, std::numeric_limits<uint16_t>::max());
    record_coverage(event.address, size);
  }
}

template <coverage_mode mode>
void coverage_tracer<mode>::on_instruction_pre(
    w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  (void) vm;
  (void) gpr;
  (void) fpr;
  (void) ctx;

  if constexpr (mode == coverage_mode::instruction) {
    if (event.address == 0) {
      return;
    }

    uint32_t size = event.size > 0 ? event.size : 1;
    size = std::min<uint32_t>(size, std::numeric_limits<uint16_t>::max());
    record_coverage(event.address, size);
  }
}

template <coverage_mode mode>
void coverage_tracer<mode>::record_coverage(uint64_t address, uint32_t size) {
  if (!engine_ || size == 0 || address == 0) {
    return;
  }

  if (!writer_.active()) {
    writer_ = engine_->begin_thread();
  }
  writer_.record(static_cast<QBDI::rword>(address), static_cast<uint16_t>(size));
}

template <coverage_mode mode> size_t coverage_tracer<mode>::get_coverage_unit_count() const {
  return engine_ ? engine_->coverage_unit_count() : 0;
}

template <coverage_mode mode> size_t coverage_tracer<mode>::get_module_count() const {
  return engine_ ? engine_->module_count() : 0;
}

template <coverage_mode mode> uint64_t coverage_tracer<mode>::get_total_hits() const {
  return engine_ ? engine_->total_hits() : 0;
}

template class coverage_tracer<coverage_mode::basic_block>;
template class coverage_tracer<coverage_mode::instruction>;

} // namespace w1cov
