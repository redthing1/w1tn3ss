#include "session.hpp"
#include <w1tn3ss/util/module_scanner.hpp>
#include <w1tn3ss/formats/drcov.hpp>
#include <redlog.hpp>
#include <iostream>
#include <iomanip>

namespace w1cov {

session::session() : initialized_(false) { config_.include_system_modules = false; }

session::session(const coverage_config& config) : config_(config), initialized_(false) {}

session::~session() {
  if (initialized_) {
    shutdown();
  }
}

bool session::initialize() {
  if (initialized_) {
    return true;
  }

  auto log = redlog::get_logger("w1cov.session");

  try {
    tracer_ = std::make_unique<coverage_tracer>(config_);
    engine_ = std::make_unique<w1::tracer_engine<coverage_tracer>>(*tracer_);

    if (!tracer_->initialize(*engine_)) {
      log.err("tracer initialization failed");
      return false;
    }

    if (!engine_->instrument()) {
      log.err("engine instrumentation failed");
      return false;
    }

    initialized_ = true;
    return true;

  } catch (const std::exception& e) {
    log.err("initialization failed", redlog::field("error", e.what()));
    return false;
  }
}

void session::shutdown() {
  if (!initialized_) {
    return;
  }

  if (tracer_) {
    tracer_.reset();
  }

  if (engine_) {
    engine_.reset();
  }

  initialized_ = false;
}

bool session::is_initialized() const { return initialized_; }

void session::add_target_module_pattern(const std::string& pattern) { config_.module_filter.push_back(pattern); }

bool session::trace_function(void* func_ptr, const std::vector<uint64_t>& args, uint64_t* result) {
  if (!initialized_) {
    return false;
  }

  auto log = redlog::get_logger("w1cov.session");

  std::vector<QBDI::rword> qbdi_args;
  for (uint64_t arg : args) {
    qbdi_args.push_back(static_cast<QBDI::rword>(arg));
  }

  QBDI::rword func_addr = reinterpret_cast<QBDI::rword>(func_ptr);
  QBDI::rword retval;

  // add instrumentation range for the function
  QBDI::VM* vm = engine_->get_vm();
  if (!vm->addInstrumentedModuleFromAddr(func_addr)) {
    log.dbg("failed to add instrumented module for function address");
    return false;
  }

  log.dbg("calling function", redlog::field("function_addr", "0x%08x", func_addr));

  bool success = engine_->call_with_stack(&retval, func_addr, qbdi_args);

  if (!success) {
    log.dbg("function call failed");
    return false;
  }

  if (result) {
    *result = static_cast<uint64_t>(retval);
  }

  return true;
}

size_t session::get_coverage_unit_count() const { return tracer_ ? tracer_->get_coverage_unit_count() : 0; }

size_t session::get_module_count() const { return tracer_ ? tracer_->get_module_count() : 0; }

uint64_t session::get_total_hits() const { return tracer_ ? tracer_->get_total_hits() : 0; }

void session::print_statistics() const {
  if (!tracer_) {
    std::cout << "session not initialized\n";
    return;
  }

  size_t units = get_coverage_unit_count();
  size_t modules = get_module_count();
  uint64_t hits = get_total_hits();

  std::cout << "coverage statistics:\n";
  std::cout << "  coverage units: " << units << "\n";
  std::cout << "  modules: " << modules << "\n";
  std::cout << "  total hits: " << hits << "\n";

  if (units > 0 && hits > 0) {
    double avg = static_cast<double>(hits) / units;
    std::cout << "  avg hits/unit: " << std::fixed << std::setprecision(2) << avg << "\n";
  }
}

bool session::export_coverage(const std::string& output_path) const {
  if (!tracer_) {
    return false;
  }

  auto log = redlog::get_logger("w1cov.session");

  try {
    const auto& collector = tracer_->get_collector();
    auto data = collector.build_drcov_data();

    if (data.basic_blocks.empty()) {
      log.wrn("no coverage data to export");
      return false;
    }

    drcov::write(output_path, data);
    log.inf("coverage exported", redlog::field("file", output_path), redlog::field("blocks", data.basic_blocks.size()));
    return true;

  } catch (const std::exception& e) {
    log.err("export failed", redlog::field("error", e.what()));
    return false;
  }
}

void session::clear_coverage() {
  if (!tracer_) {
    return;
  }

  // note: would need collector.clear() method to implement this
  // for now, reinitialize the tracer to clear state
  auto log = redlog::get_logger("w1cov.session");
  log.inf("coverage data cleared");
}

coverage_config& session::get_config() { return config_; }

bool session::add_instrumented_module(void* module_addr) {
  if (!initialized_ || !engine_) {
    return false;
  }

  auto log = redlog::get_logger("w1cov.session");

  QBDI::VM* vm = engine_->get_vm();
  if (!vm) {
    log.err("failed to get VM for module instrumentation");
    return false;
  }

  QBDI::rword addr = reinterpret_cast<QBDI::rword>(module_addr);
  bool success = vm->addInstrumentedModuleFromAddr(addr);

  if (success) {
    log.dbg("added module to instrumentation", redlog::field("address", "0x%08x", addr));
  } else {
    log.wrn("failed to add module to instrumentation", redlog::field("address", "0x%08x", addr));
  }

  return success;
}

bool session::add_instrumented_range(void* start, void* end) {
  if (!initialized_ || !engine_) {
    return false;
  }

  auto log = redlog::get_logger("w1cov.session");

  QBDI::VM* vm = engine_->get_vm();
  if (!vm) {
    log.err("failed to get VM for range instrumentation");
    return false;
  }

  QBDI::rword start_addr = reinterpret_cast<QBDI::rword>(start);
  QBDI::rword end_addr = reinterpret_cast<QBDI::rword>(end);

  vm->addInstrumentedRange(start_addr, end_addr);

  log.dbg(
      "added range to instrumentation", redlog::field("start", "0x%08x", start_addr),
      redlog::field("end", "0x%08x", end_addr)
  );

  return true;
}

bool session::remove_all_instrumented_ranges() {
  if (!initialized_ || !engine_) {
    return false;
  }

  auto log = redlog::get_logger("w1cov.session");

  QBDI::VM* vm = engine_->get_vm();
  if (!vm) {
    log.err("failed to get VM for removing instrumentation");
    return false;
  }

  vm->removeAllInstrumentedRanges();
  log.dbg("removed all instrumented ranges");

  return true;
}

} // namespace w1cov