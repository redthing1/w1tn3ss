#include "coverage_tracer.hpp"
#include <w1tn3ss/formats/drcov.hpp>
#include <redlog/redlog.hpp>
#include <fstream>

namespace w1cov {

coverage_tracer::coverage_tracer(const coverage_config& config) : config_(config), module_tracker_(config) {}

bool coverage_tracer::initialize(w1::tracer_engine<coverage_tracer>& engine) {
  auto log = redlog::get_logger("w1cov.tracer");

  log.vrb("initializing coverage tracer");

  // initialize module tracker with collector
  module_tracker_.initialize(collector_);

  log.info("tracer initialization completed", redlog::field("traced_modules", module_tracker_.traced_module_count()));

  return true;
}

void coverage_tracer::shutdown() {
  auto log = redlog::get_logger("w1cov.tracer");

  size_t bb_count = collector_.get_basic_block_count();
  size_t module_count = collector_.get_module_count();
  uint64_t total_hits = collector_.get_total_hits();

  log.info(
      "coverage collection completed", redlog::field("basic_blocks", bb_count), redlog::field("modules", module_count),
      redlog::field("total_hits", total_hits)
  );
}

QBDI::VMAction coverage_tracer::on_basic_block_entry(
    QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  // hot path: no logging, minimal validation
  if (!state) {
    return QBDI::VMAction::CONTINUE;
  }

  QBDI::rword block_addr = state->basicBlockStart;
  QBDI::rword block_size = state->basicBlockEnd - state->basicBlockStart;

  // basic validation without logging
  if (block_size == 0 || block_addr == 0) {
    return QBDI::VMAction::CONTINUE;
  }

  // hot path: single visitor call, zero allocations, integrated filtering
  bool found =
      module_tracker_.visit_traced_module(block_addr, [&](const w1::util::module_info& mod, uint16_t module_id) {
        collector_.record_basic_block(block_addr, static_cast<uint16_t>(block_size), module_id);
      });

  // rare path: attempt rescanning if module not found
  if (!found) {
    module_tracker_.try_rescan_and_visit(block_addr, [&](const w1::util::module_info& mod, uint16_t module_id) {
      collector_.record_basic_block(block_addr, static_cast<uint16_t>(block_size), module_id);
    });
  }

  return QBDI::VMAction::CONTINUE;
}

size_t coverage_tracer::get_basic_block_count() const { return collector_.get_basic_block_count(); }

size_t coverage_tracer::get_module_count() const { return collector_.get_module_count(); }

uint64_t coverage_tracer::get_total_hits() const { return collector_.get_total_hits(); }

void coverage_tracer::print_statistics() const {
  auto log = redlog::get_logger("w1cov.tracer");

  size_t bb_count = collector_.get_basic_block_count();
  size_t module_count = collector_.get_module_count();
  uint64_t total_hits = collector_.get_total_hits();
  size_t traced_modules = module_tracker_.traced_module_count();

  log.inf("=== Coverage Statistics ===");
  log.inf("basic blocks hit", redlog::field("count", bb_count));
  log.inf("modules instrumented", redlog::field("count", module_count));
  log.inf("traced modules", redlog::field("count", traced_modules));
  log.inf("total hits", redlog::field("count", total_hits));

  if (bb_count > 0 && total_hits > 0) {
    double avg_hits = static_cast<double>(total_hits) / bb_count;
    log.inf("average hits per block", redlog::field("average", "%.2f", avg_hits));
  }
}

const coverage_collector& coverage_tracer::get_collector() const { return collector_; }

} // namespace w1cov