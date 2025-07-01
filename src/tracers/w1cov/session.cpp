#include "session.hpp"
#include <w1tn3ss/util/module_scanner.hpp>
#include <redlog/redlog.hpp>

namespace w1cov {

session::session() : initialized_(false) {
  config_.output_file = "coverage.drcov";
  config_.exclude_system_modules = true;
  config_.track_hitcounts = true;
}

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

  auto log = redlog::get_logger("w1cov.standalone");

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
    tracer_->shutdown();
    tracer_.reset();
  }

  if (engine_) {
    engine_.reset();
  }

  initialized_ = false;
}

bool session::is_initialized() const { return initialized_; }

void session::set_output_file(const std::string& filepath) { config_.output_file = filepath; }

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
    log.err("failed to add instrumented module for function address");
    return false;
  }

  log.inf("calling function", redlog::field("function_addr", "0x%08x", func_addr));
  bool success = engine_->call(&retval, func_addr, qbdi_args);
  log.inf("function call result", redlog::field("success", success), redlog::field("retval", retval));

  if (success && result) {
    *result = static_cast<uint64_t>(retval);
  }

  return success;
}

size_t session::get_basic_block_count() const { return tracer_ ? tracer_->get_basic_block_count() : 0; }

uint64_t session::get_total_hits() const { return tracer_ ? tracer_->get_total_hits() : 0; }

coverage_config& session::get_config() { return config_; }

} // namespace w1cov