#include "coverage_tracer.hpp"
#include <w1tn3ss/formats/drcov.hpp>
#include <redlog/redlog.hpp>
#include <fstream>

namespace w1cov {

coverage_tracer::coverage_tracer(const coverage_config& config) : config_(config) {}

bool coverage_tracer::initialize(w1::tracer_engine<coverage_tracer>& engine) {
  auto log = redlog::get_logger("w1cov.tracer");

  discoverer_.take_snapshot();
  update_module_filter();

  auto modules = discoverer_.get_modules();
  size_t instrumented_count = 0;

  for (const auto& mod : modules) {
    if (should_trace_module(mod)) {
      uint16_t module_id = collector_.add_module(mod);
      allowed_module_bases_.insert(mod.base_address);
      module_base_to_id_[mod.base_address] = module_id;

      log.dbg(
          "tracing module", redlog::field("module_name", mod.name), redlog::field("module_id", module_id),
          redlog::field("base_address", "0x%08x", mod.base_address)
      );

      instrumented_count++;
    }
  }

  log.info(
      "tracer initialization completed", redlog::field("total_modules", modules.size()),
      redlog::field("instrumented_modules", instrumented_count)
  );

  return true;
}

void coverage_tracer::shutdown() {
  auto log = redlog::get_logger("w1cov.tracer");
  log.vrb("shutdown initiated");

  size_t bb_count = collector_.get_basic_block_count();
  size_t module_count = collector_.get_module_count();

  log.info(
      "coverage collection completed", redlog::field("basic_blocks", bb_count), redlog::field("modules", module_count)
  );

  // Early return if no data to export
  if (bb_count == 0) {
    log.wrn("no basic blocks collected, skipping export");
    return;
  }

  try {
    log.vrb("opening output file", redlog::field("output_file", config_.output_file));
    std::ofstream file(config_.output_file, std::ios::binary);
    if (!file) {
      log.err("failed to open output file", redlog::field("output_file", config_.output_file));
      return;
    }

    log.vrb("building coverage data");
    drcov::coverage_data data = collector_.build_drcov_data();
    log.vrb("coverage data built successfully");

    log.vrb("writing coverage data to file");
    try {
      drcov::write(file, data);
      log.vrb("coverage data written successfully");
    } catch (const std::exception& write_e) {
      log.err("exception during drcov write", redlog::field("error", write_e.what()));
      throw;
    } catch (...) {
      log.err("unknown exception during drcov write");
      throw;
    }

    file.close();
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
  auto logger = redlog::get_logger("w1cov.tracer");

  if (!state) {
    logger.wrn("null vm state received, skipping basic block");
    return QBDI::VMAction::CONTINUE;
  }

  QBDI::rword block_addr = state->basicBlockStart;
  QBDI::rword block_size = state->basicBlockEnd - state->basicBlockStart;

  if (block_size == 0) {
    logger.wrn("zero-sized basic block encountered", redlog::field("address", "0x%08x", block_addr));
    return QBDI::VMAction::CONTINUE;
  }

  if (block_addr == 0) {
    logger.wrn("null address basic block encountered", redlog::field("size", block_size));
    return QBDI::VMAction::CONTINUE;
  }

  // check what module is at this address
  const auto& mod = discoverer_.get_module_for_address(block_addr);

  if (mod.type == w1::util::module_type::UNKNOWN) {
    // no known module there, try rescanning
    logger.trc(
        "unknown module at address, attempting rescanning", redlog::field("address", "0x%08x", block_addr),
        redlog::field("size", block_size)
    );

    std::unique_lock<std::mutex> lock(rescan_mutex_, std::try_to_lock);
    if (lock.owns_lock()) {
      discoverer_.take_snapshot();
      update_module_filter();

      const auto& updated_mod = discoverer_.get_module_for_address(block_addr);
      if (updated_mod.type != w1::util::module_type::UNKNOWN && should_trace_module(updated_mod)) {

        uint16_t module_id = collector_.add_module(updated_mod);
        module_base_to_id_[updated_mod.base_address] = module_id;
        allowed_module_bases_.insert(updated_mod.base_address);

        logger.trc(
            "discovered new module during rescanning", redlog::field("module_name", updated_mod.name),
            redlog::field("module_id", module_id)
        );

        // now record this basic block
        collector_.record_basic_block(block_addr, block_size, module_id);
      } else {
        logger.wrn(
            "failed to discover module during rescanning", redlog::field("address", "0x%08x", block_addr),
            redlog::field("module_type", static_cast<int>(updated_mod.type))
        );
      }
    } else {
      logger.dbg("rescan already in progress, skipping basic block", redlog::field("address", "0x%08x", block_addr));
    }
    return QBDI::VMAction::CONTINUE;
  }

  if (allowed_module_bases_.count(mod.base_address) == 0) {
    logger.dbg(
        "basic block not in allowed module", redlog::field("address", "0x%08x", block_addr),
        redlog::field("module_name", mod.name), redlog::field("module_base", "0x%08x", mod.base_address)
    );
    return QBDI::VMAction::CONTINUE;
  }

  auto it = module_base_to_id_.find(mod.base_address);
  if (it == module_base_to_id_.end()) {
    logger.wrn(
        "module base in allowed set but not in id mapping", redlog::field("address", "0x%08x", block_addr),
        redlog::field("module_name", mod.name), redlog::field("module_base", "0x%08x", mod.base_address)
    );
    return QBDI::VMAction::CONTINUE;
  }
  auto module_id = it->second;

  collector_.record_basic_block(block_addr, block_size, module_id);

  return QBDI::VMAction::CONTINUE;
}

void coverage_tracer::update_module_filter() {
  allowed_module_bases_.clear();

  auto modules = discoverer_.get_modules();
  for (const auto& mod : modules) {
    if (should_trace_module(mod)) {
      allowed_module_bases_.insert(mod.base_address);
    }
  }
}

bool coverage_tracer::should_trace_module(const w1::util::module_info& mod) const {
  if (mod.type == w1::util::module_type::UNKNOWN) {
    return false;
  }

  if (!config_.module_filter.empty()) {
    for (const auto& target : config_.module_filter) {
      if (mod.name.find(target) != std::string::npos) {
        return true;
      }
    }
    return false;
  }

  if (config_.exclude_system_modules && mod.is_system_library) {
    return false;
  }

  return true;
}

} // namespace w1cov