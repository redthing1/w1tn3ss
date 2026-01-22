#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>

#include <QBDI.h>

#include "w1instrument/core/module_cache.hpp"
#include "w1instrument/core/thread_buffer.hpp"
#include "w1instrument/tracer/event.hpp"
#include "w1instrument/tracer/trace_context.hpp"
#include "w1instrument/tracer/tracer.hpp"
#include "w1instrument/tracer/types.hpp"

#include "engine/coverage_engine.hpp"
#include "engine/coverage_store.hpp"

namespace w1cov {

enum class coverage_mode : uint8_t { basic_block, instruction };

template <coverage_mode mode> class coverage_recorder {
public:
  explicit coverage_recorder(std::shared_ptr<coverage_engine> engine, uint64_t flush_threshold = 0);

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

  struct buffer_merge {
    coverage_engine* engine = nullptr;

    void operator()(const coverage_buffer& buffer) const {
      if (engine) {
        engine->merge_buffer(buffer);
      }
    }
  };

  using buffer_type = w1::core::thread_buffer<uint64_t, coverage_buffer_entry, buffer_merge>;

  std::shared_ptr<coverage_engine> engine_;
  uint64_t module_epoch_ = 0;
  w1::core::module_cache<uint16_t> module_cache_{};
  buffer_type buffer_;
};

} // namespace w1cov
