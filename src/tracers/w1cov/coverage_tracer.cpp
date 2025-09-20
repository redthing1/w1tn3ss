#include "coverage_tracer.hpp"
#include <w1tn3ss/formats/drcov.hpp>
#include <w1tn3ss/util/register_access.hpp>
#include <redlog.hpp>
#include <algorithm>
#include <fstream>
#include <limits>

namespace w1cov {

coverage_tracer::coverage_tracer(const coverage_config& config) : config_(config), module_tracker_(config) {}

bool coverage_tracer::initialize(w1::tracer_engine<coverage_tracer>& engine) {
  auto log = redlog::get_logger("w1cov.tracer");

  log.vrb("initializing coverage tracer");

  // initialize module tracker with collector
  module_tracker_.initialize(collector_);

  // manually register the appropriate callback based on mode
  QBDI::VM* vm = engine.get_vm();
  if (config_.inst_trace) {
    // register instruction-level tracing callback
    uint32_t id = vm->addCodeCB(
        QBDI::PREINST,
        [](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data) -> QBDI::VMAction {
          auto* tracer = static_cast<coverage_tracer*>(data);
          return tracer->on_instruction_preinst_manual(vm, gpr, fpr);
        },
        this
    );
    log.info("registered instruction preinst callback", redlog::field("id", id));
  } else {
    // register basic block tracing callback
    uint32_t id = vm->addVMEventCB(
        QBDI::BASIC_BLOCK_ENTRY,
        [](QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr,
           void* data) -> QBDI::VMAction {
          auto* tracer = static_cast<coverage_tracer*>(data);
          return tracer->on_basic_block_entry_manual(vm, state, gpr, fpr);
        },
        this
    );
    log.info("registered basic block entry callback", redlog::field("id", id));
  }

  log.info(
      "tracer initialization completed", redlog::field("traced_modules", module_tracker_.traced_module_count()),
      redlog::field("inst_trace", config_.inst_trace)
  );

  return true;
}

void coverage_tracer::shutdown() {
  auto log = redlog::get_logger("w1cov.tracer");

  size_t unit_count = collector_.get_coverage_unit_count();
  size_t module_count = collector_.get_module_count();
  uint64_t total_hits = collector_.get_total_hits();

  log.info(
      "coverage collection completed", redlog::field("coverage_units", unit_count),
      redlog::field("modules", module_count), redlog::field("total_hits", total_hits)
  );
}

QBDI::VMAction coverage_tracer::on_basic_block_entry_manual(
    QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  // hot path: no logging, minimal validation
  if (!state) {
    return QBDI::VMAction::CONTINUE;
  }

  QBDI::rword block_addr = state->basicBlockStart;
  QBDI::rword block_size = state->basicBlockEnd - state->basicBlockStart;

  record_coverage_at_address(block_addr, static_cast<uint16_t>(block_size));

  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction coverage_tracer::on_instruction_preinst_manual(
    QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  // hot path: no logging, minimal validation
  if (!gpr) {
    return QBDI::VMAction::CONTINUE;
  }

  // get current instruction address
  QBDI::rword inst_addr = w1::registers::get_pc(gpr);

  // basic validation
  if (inst_addr == 0) {
    return QBDI::VMAction::CONTINUE;
  }

  uint16_t inst_size = 1;

  // if (auto* vm_ptr = static_cast<QBDI::VM*>(vm)) {
  //   const QBDI::InstAnalysis* analysis = vm_ptr->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION);
  //   if (analysis && analysis->instSize > 0) {
  //     inst_size = static_cast<uint16_t>(std::min<uint32_t>(analysis->instSize,
  //     std::numeric_limits<uint16_t>::max()));
  //   }
  // }

  // let's just use block size 1 to avoid inst analysis overhead
  // this also is a sentinel value indicating inst trace

  record_coverage_at_address(inst_addr, inst_size);

  return QBDI::VMAction::CONTINUE;
}

void coverage_tracer::record_coverage_at_address(QBDI::rword address, uint16_t size) {
  // basic validation without logging
  if (size == 0 || address == 0) {
    return;
  }

  // hot path: single visitor call, zero allocations, integrated filtering
  bool found = module_tracker_.visit_traced_module(address, [&](const w1::util::module_info& mod, uint16_t module_id) {
    collector_.record_coverage_unit(address, size, module_id);
  });

  // rare path: attempt rescanning if module not found
  if (!found) {
    module_tracker_.try_rescan_and_visit(address, [&](const w1::util::module_info& mod, uint16_t module_id) {
      collector_.record_coverage_unit(address, size, module_id);
    });
  }
}

size_t coverage_tracer::get_coverage_unit_count() const { return collector_.get_coverage_unit_count(); }

size_t coverage_tracer::get_module_count() const { return collector_.get_module_count(); }

uint64_t coverage_tracer::get_total_hits() const { return collector_.get_total_hits(); }

void coverage_tracer::print_statistics() const {
  auto log = redlog::get_logger("w1cov.tracer");

  size_t unit_count = collector_.get_coverage_unit_count();
  size_t module_count = collector_.get_module_count();
  uint64_t total_hits = collector_.get_total_hits();
  size_t traced_modules = module_tracker_.traced_module_count();

  log.inf("=== Coverage Statistics ===");
  log.inf("coverage units hit", redlog::field("count", unit_count));
  log.inf("modules instrumented", redlog::field("count", module_count));
  log.inf("traced modules", redlog::field("count", traced_modules));
  log.inf("total hits", redlog::field("count", total_hits));

  if (unit_count > 0 && total_hits > 0) {
    double avg_hits = static_cast<double>(total_hits) / unit_count;
    log.inf("average hits per unit", redlog::field("average", "%.2f", avg_hits));
  }
}

const coverage_collector& coverage_tracer::get_collector() const { return collector_; }

} // namespace w1cov
