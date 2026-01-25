#include "coverage_thread_tracer.hpp"

#include <algorithm>
#include <optional>

namespace w1cov {

namespace {
constexpr size_t kDefaultBufferReserve = 4096;
}

template <coverage_mode mode>
coverage_thread_tracer<mode>::coverage_thread_tracer(std::shared_ptr<coverage_engine> engine, uint64_t flush_threshold)
    : engine_(std::move(engine)), module_epoch_(engine_ ? engine_->module_epoch() : 0),
      buffer_(buffer_merge{engine_.get()}, kDefaultBufferReserve, flush_threshold) {}

template <coverage_mode mode>
void coverage_thread_tracer<mode>::on_thread_start(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  (void) event;
  if (engine_) {
    module_epoch_ = engine_->module_epoch();
  }
  module_cache_.reset();
  buffer_.clear();
}

template <coverage_mode mode>
void coverage_thread_tracer<mode>::on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  (void) event;
  if (!engine_) {
    return;
  }
  buffer_.flush();
  module_cache_.reset();
}

template <coverage_mode mode>
void coverage_thread_tracer<mode>::on_basic_block_entry(
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
void coverage_thread_tracer<mode>::on_instruction_pre(
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

template <coverage_mode mode> void coverage_thread_tracer<mode>::record_coverage(uint64_t address, uint32_t size) {
  if (!engine_ || size == 0 || address == 0) {
    return;
  }

  const uint64_t current_epoch = engine_->module_epoch();
  if (current_epoch != module_epoch_) {
    buffer_.flush();
    module_cache_.reset();
    module_epoch_ = current_epoch;
  }

  buffer_.record(
      address,
      [&](coverage_buffer_entry& entry) {
        if (entry.size == 0 && size != 0) {
          entry.size = static_cast<uint16_t>(size);
        }
        entry.hits += 1;
      },
      [&]() -> std::optional<coverage_buffer_entry> {
        auto module_id =
            module_cache_.resolve(address, current_epoch, [&](uint64_t addr) { return engine_->find_module(addr); });
        if (!module_id) {
          return std::nullopt;
        }

        coverage_buffer_entry entry{};
        entry.module_id = *module_id;
        entry.size = static_cast<uint16_t>(size);
        entry.hits = 1;
        return entry;
      }
  );
}

template class coverage_thread_tracer<coverage_mode::basic_block>;
template class coverage_thread_tracer<coverage_mode::instruction>;

} // namespace w1cov
