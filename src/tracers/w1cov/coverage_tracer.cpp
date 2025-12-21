#include "coverage_tracer.hpp"

#include <algorithm>
#include <utility>

#include "w1tn3ss/formats/drcov.hpp"

namespace w1cov {

template <coverage_mode mode>
coverage_tracer<mode>::coverage_tracer(coverage_config config)
    : config_(std::move(config)), module_tracker_(config_), log_(redlog::get_logger("w1cov.tracer")) {}

template <coverage_mode mode>
void coverage_tracer<mode>::on_thread_start(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) event;
  if (initialized_) {
    return;
  }

  log_.vrb("initializing coverage tracer");
  module_tracker_.initialize(ctx.modules(), collector_);
  log_.inf(
      "tracer initialization completed", redlog::field("traced_modules", module_tracker_.traced_module_count()),
      redlog::field("inst_trace", config_.inst_trace)
  );
  initialized_ = true;
}

template <coverage_mode mode>
void coverage_tracer<mode>::on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  if (!exported_) {
    export_coverage();
  }

  log_.inf(
      "coverage collection completed", redlog::field("coverage_units", get_coverage_unit_count()),
      redlog::field("modules", get_module_count()), redlog::field("total_hits", get_total_hits())
  );
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

  if constexpr (mode == coverage_mode::basic_block) {
    if (event.address == 0 || event.size == 0) {
      return;
    }

    uint32_t size = std::min<uint32_t>(event.size, std::numeric_limits<uint16_t>::max());
    record_coverage(ctx, event.address, size);
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

  if constexpr (mode == coverage_mode::instruction) {
    if (event.address == 0) {
      return;
    }

    uint32_t size = event.size > 0 ? event.size : 1;
    size = std::min<uint32_t>(size, std::numeric_limits<uint16_t>::max());
    record_coverage(ctx, event.address, size);
  }
}

template <coverage_mode mode>
void coverage_tracer<mode>::record_coverage(w1::trace_context& ctx, uint64_t address, uint32_t size) {
  if (size == 0 || address == 0) {
    return;
  }

  if (!initialized_) {
    module_tracker_.initialize(ctx.modules(), collector_);
    initialized_ = true;
  }

  module_tracker_.visit_traced_module(ctx.modules(), address, [&](const w1::runtime::module_info&, uint16_t module_id) {
    collector_.record_coverage_unit(address, static_cast<uint16_t>(size), module_id);
  });
}

template <coverage_mode mode> void coverage_tracer<mode>::export_coverage() {
  exported_ = true;

  try {
    auto data = collector_.build_drcov_data();
    if (data.basic_blocks.empty()) {
      log_.wrn("no coverage data collected; skipping export");
      return;
    }

    drcov::write(config_.output_file, data);
    log_.inf("coverage data export completed", redlog::field("output_file", config_.output_file));
  } catch (const std::exception& error) {
    log_.err("coverage export failed", redlog::field("error", error.what()));
  }
}

template class coverage_tracer<coverage_mode::basic_block>;
template class coverage_tracer<coverage_mode::instruction>;

} // namespace w1cov
