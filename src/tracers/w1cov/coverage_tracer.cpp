#include "coverage_tracer.hpp"
#include <w1tn3ss/formats/drcov.hpp>
#include <redlog/redlog.hpp>
#include <fstream>

namespace w1cov {

coverage_tracer::coverage_tracer(const coverage_config& config) 
    : config_(config), module_tracker_(config) {}

bool coverage_tracer::initialize(w1::tracer_engine<coverage_tracer>& engine) {
    auto log = redlog::get_logger("w1cov.tracer");
    
    log.vrb("initializing coverage tracer");
    
    // initialize module tracker with collector
    module_tracker_.initialize(collector_);
    
    log.info("tracer initialization completed", 
             redlog::field("traced_modules", module_tracker_.traced_module_count()));
    
    return true;
}

void coverage_tracer::shutdown() {
  auto log = redlog::get_logger("w1cov.tracer");
  log.vrb("shutdown initiated");

  size_t bb_count = collector_.get_basic_block_count();
  size_t module_count = collector_.get_module_count();
  uint64_t total_hits = collector_.get_total_hits();

  log.info(
      "coverage collection completed", redlog::field("basic_blocks", bb_count), 
      redlog::field("modules", module_count), redlog::field("total_hits", total_hits)
  );

  // Early return if no data to export
  if (bb_count == 0) {
    log.wrn("no basic blocks collected, skipping export");
    return;
  }

  try {
    log.vrb("building coverage data with drcov builder");
    drcov::coverage_data data = collector_.build_drcov_data();
    log.vrb("coverage data built successfully", redlog::field("modules", data.modules.size()), 
            redlog::field("basic_blocks", data.basic_blocks.size()));

    // validate export data before writing
    if (data.modules.empty()) {
      log.wrn("no modules in coverage data, creating empty file");
    }
    
    if (data.basic_blocks.empty()) {
      log.wrn("no basic blocks in coverage data");
    }

    log.vrb("writing coverage data to file", redlog::field("output_file", config_.output_file));
    
    try {
      drcov::write(config_.output_file, data);
      log.vrb("coverage data written successfully");
    } catch (const std::exception& write_e) {
      log.err("exception during drcov write", redlog::field("error", write_e.what()));
      throw;
    } catch (...) {
      log.err("unknown exception during drcov write");
      throw;
    }

    // verify file was created
    std::ifstream verify_file(config_.output_file);
    if (!verify_file.good()) {
      log.err("output file verification failed", redlog::field("output_file", config_.output_file));
      return;
    }
    verify_file.close();

    log.info("coverage data export completed", redlog::field("output_file", config_.output_file));

  } catch (const std::exception& e) {
    log.err("exception during coverage export", redlog::field("error", e.what()));
    return;
  } catch (...) {
    log.err("unknown exception during coverage export");
    return;
  }

  log.vrb("shutdown completed");
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
    bool found = module_tracker_.visit_traced_module(block_addr, 
        [&](const w1::util::module_info& mod, uint16_t module_id) {
            collector_.record_basic_block(block_addr, static_cast<uint16_t>(block_size), module_id);
        });

    // rare path: attempt rescanning if module not found
    if (!found) {
        module_tracker_.try_rescan_and_visit(block_addr,
            [&](const w1::util::module_info& mod, uint16_t module_id) {
                collector_.record_basic_block(block_addr, static_cast<uint16_t>(block_size), module_id);
            });
    }

    return QBDI::VMAction::CONTINUE;
}

} // namespace w1cov