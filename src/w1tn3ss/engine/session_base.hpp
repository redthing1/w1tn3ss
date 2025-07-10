#pragma once

#include "tracer_engine.hpp"
#include <QBDI.h>
#include <memory>
#include <vector>
#include <redlog.hpp>

namespace w1 {

// simple crtp base that eliminates boilerplate for tracer sessions
template <typename Derived, typename TTracer, typename TConfig> class session_base {
public:
  using tracer_type = TTracer;
  using config_type = TConfig;

protected:
  config_type config_;
  std::unique_ptr<TTracer> tracer_;
  std::unique_ptr<tracer_engine<TTracer>> engine_;
  bool initialized_ = false;

public:
  session_base() = default;
  explicit session_base(const config_type& config) : config_(config) {}

  virtual ~session_base() {
    if (initialized_) {
      shutdown();
    }
  }

  // basic lifecycle - same as current w1cov::session
  bool initialize() {
    if (initialized_) {
      return true;
    }

    auto log = redlog::get_logger("w1.session_base");

    try {
      tracer_ = std::make_unique<TTracer>(config_);
      engine_ = std::make_unique<tracer_engine<TTracer>>(*tracer_);

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

  void shutdown() {
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

  bool is_initialized() const { return initialized_; }

  // configuration access
  config_type& get_config() { return config_; }
  const config_type& get_config() const { return config_; }

  // module pattern helpers
  void add_target_module_pattern(const std::string& pattern) { config_.module_filter.push_back(pattern); }

  // standard trace function - exactly like current implementation
  bool trace_function(void* func_ptr, const std::vector<uint64_t>& args = {}, uint64_t* result = nullptr) {
    if (!initialized_) {
      return false;
    }

    auto log = redlog::get_logger("w1.session_base");

    QBDI::VM* vm = engine_->get_vm();
    if (!vm) {
      return false;
    }

    QBDI::rword func_addr = reinterpret_cast<QBDI::rword>(func_ptr);

    // add instrumentation for the function
    if (!vm->addInstrumentedModuleFromAddr(func_addr)) {
      log.dbg("failed to add instrumented module for function address");
      return false;
    }

    // convert args
    std::vector<QBDI::rword> qbdi_args;
    for (uint64_t arg : args) {
      qbdi_args.push_back(static_cast<QBDI::rword>(arg));
    }

    log.dbg("calling function", redlog::field("function_addr", "0x%08x", func_addr));

    // call the function
    QBDI::rword retval;
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

  // direct vm access for power users
  QBDI::VM* get_vm() const { return engine_ ? engine_->get_vm() : nullptr; }

  tracer_engine<TTracer>* get_engine() const { return engine_.get(); }

  // instrumentation control
  bool add_instrumented_module_from_addr(void* module_addr) {
    if (!initialized_ || !engine_) {
      return false;
    }

    auto log = redlog::get_logger("w1.session_base");

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

  bool add_instrumented_range(void* start, void* end) {
    if (!initialized_ || !engine_) {
      return false;
    }

    auto log = redlog::get_logger("w1.session_base");

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

  bool remove_all_instrumented_ranges() {
    if (!initialized_ || !engine_) {
      return false;
    }

    auto log = redlog::get_logger("w1.session_base");

    QBDI::VM* vm = engine_->get_vm();
    if (!vm) {
      log.err("failed to get VM for removing instrumentation");
      return false;
    }

    vm->removeAllInstrumentedRanges();
    log.dbg("removed all instrumented ranges");

    return true;
  }

protected:
  // protected accessors for derived classes
  TTracer* get_tracer() { return tracer_.get(); }
  const TTracer* get_tracer() const { return tracer_.get(); }
};

} // namespace w1