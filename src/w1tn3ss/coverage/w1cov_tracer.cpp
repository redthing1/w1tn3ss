#include "w1cov_tracer.hpp"
#include "coverage_data.hpp"
#include "module_mapper.hpp"
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#endif

// qbdi includes
#include <QBDI.h>

namespace w1::coverage {

w1cov_tracer::w1cov_tracer()
    : log_(redlog::get_logger("w1tn3ss.w1cov")), initialized_(false), instrumenting_(false), qbdi_vm_(nullptr),
      output_file_("coverage.drcov"), exclude_system_(true), callback_count_(0), instrumentation_start_time_(0),
      last_stats_time_(0) {
  log_.debug("w1cov tracer created");
}

w1cov_tracer::~w1cov_tracer() {
  if (is_instrumenting()) {
    stop_instrumentation();
  }

  if (is_initialized()) {
    shutdown();
  }

  log_.debug("w1cov tracer destroyed");
}

bool w1cov_tracer::initialize() {
  if (initialized_) {
    log_.warn("tracer already initialized");
    return true;
  }

  log_.info("initializing w1cov tracer");

  try {
    // create core components
    collector_ = std::make_unique<coverage_collector>();
    mapper_ = std::make_unique<module_mapper>(*collector_);

    // configure from environment
    configure_from_environment();

    // setup qbdi vm
    if (!setup_qbdi_vm()) {
      log_.error("failed to setup qbdi vm");
      return false;
    }

    initialized_ = true;
    log_.info("w1cov tracer initialized successfully");
    return true;

  } catch (const std::exception& e) {
    log_.error("initialization failed", redlog::field("error", e.what()));
    return false;
  }
}

void w1cov_tracer::shutdown() {
  if (!initialized_) {
    return;
  }

  log_.info("shutting down w1cov tracer");

  // stop instrumentation if running
  if (is_instrumenting()) {
    stop_instrumentation();
  }

  // export final coverage data
  export_coverage_data();

  // cleanup qbdi
  cleanup_qbdi_vm();

  // cleanup components
  mapper_.reset();
  collector_.reset();

  initialized_ = false;
  log_.info("w1cov tracer shutdown complete");
}

void w1cov_tracer::configure_from_environment() {
  log_.debug("configuring from environment variables");

  // check if w1cov is enabled
  if (!get_env_bool("W1COV_ENABLED", false)) {
    log_.info("w1cov not enabled via environment");
    return;
  }

  // get output file
  output_file_ = get_env_var("W1COV_OUTPUT_FILE", "coverage.drcov");
  log_.info("output file configured", redlog::field("file", output_file_));

  // get system module exclusion setting
  exclude_system_ = get_env_bool("W1COV_EXCLUDE_SYSTEM", true);
  log_.info("system module exclusion configured", redlog::field("exclude", exclude_system_));

  // configure components
  if (collector_) {
    collector_->set_exclude_system_modules(exclude_system_);
    collector_->set_output_file(output_file_);
  }

  if (mapper_) {
    mapper_->set_exclude_system_modules(exclude_system_);
  }

  // get target module patterns
  std::string target_modules = get_env_var("W1COV_TARGET_MODULES", "");
  if (!target_modules.empty()) {
    // split comma-separated patterns
    std::stringstream ss(target_modules);
    std::string pattern;
    while (std::getline(ss, pattern, ',')) {
      if (!pattern.empty() && mapper_) {
        mapper_->add_target_module_pattern(pattern);
        log_.info("added target module pattern", redlog::field("pattern", pattern));
      }
    }
  }
}

void w1cov_tracer::set_output_file(const std::string& filepath) {
  output_file_ = filepath;
  if (collector_) {
    collector_->set_output_file(filepath);
  }
}

void w1cov_tracer::set_exclude_system_modules(bool exclude) {
  exclude_system_ = exclude;
  if (collector_) {
    collector_->set_exclude_system_modules(exclude);
  }
  if (mapper_) {
    mapper_->set_exclude_system_modules(exclude);
  }
}

void w1cov_tracer::add_target_module_pattern(const std::string& pattern) {
  if (mapper_) {
    mapper_->add_target_module_pattern(pattern);
  }
}

bool w1cov_tracer::start_instrumentation() {
  if (!initialized_) {
    log_.error("tracer not initialized");
    return false;
  }

  if (instrumenting_) {
    log_.warn("instrumentation already running");
    return true;
  }

  log_.info("starting coverage instrumentation");

  try {
    // discover and register modules
    if (!discover_and_register_modules()) {
      log_.error("failed to discover modules");
      return false;
    }

    // setup instrumentation ranges
    if (!setup_instrumentation_ranges()) {
      log_.error("failed to setup instrumentation ranges");
      return false;
    }

    // register callbacks
    if (!register_callbacks()) {
      log_.error("failed to register callbacks");
      return false;
    }

    // initialize performance monitoring
    auto now = std::chrono::steady_clock::now();
    instrumentation_start_time_ = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    last_stats_time_.store(instrumentation_start_time_);
    callback_count_ = 0;

    instrumenting_ = true;

    log_.info(
        "coverage instrumentation started successfully", redlog::field("start_time", instrumentation_start_time_)
    );
    return true;

  } catch (const std::exception& e) {
    log_.error("failed to start instrumentation", redlog::field("error", e.what()));
    return false;
  }
}

bool w1cov_tracer::stop_instrumentation() {
  if (!instrumenting_) {
    return true;
  }

  log_.info("stopping coverage instrumentation");

  try {
    // qbdi cleanup is handled in cleanup_qbdi_vm()
    instrumenting_ = false;

    // calculate final performance metrics
    auto now = std::chrono::steady_clock::now();
    uint64_t end_time = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    uint64_t total_duration = end_time - instrumentation_start_time_;
    uint64_t total_callbacks = callback_count_;

    // print final statistics
    print_statistics();

    // log performance summary
    if (total_duration > 0) {
      double callbacks_per_second = (total_callbacks * 1000.0) / total_duration;

      log_.info(
          "coverage instrumentation stopped", redlog::field("duration_ms", total_duration),
          redlog::field("total_callbacks", total_callbacks), redlog::field("callbacks_per_second", callbacks_per_second)
      );
    } else {
      log_.info("coverage instrumentation stopped", redlog::field("total_callbacks", total_callbacks));
    }

    return true;

  } catch (const std::exception& e) {
    log_.error("error stopping instrumentation", redlog::field("error", e.what()));
    return false;
  }
}

bool w1cov_tracer::setup_qbdi_vm() {
  log_.info("setting up qbdi vm for coverage instrumentation");

  try {
    // create qbdi vm instance
    log_.debug("creating qbdi vm instance");
    auto* vm = new QBDI::VM();
    qbdi_vm_ = static_cast<QBDIVMPtr>(vm);

    log_.verbose("qbdi vm instance created", redlog::field("vm_ptr", vm));

    // get vm state
    log_.debug("retrieving gpr state from qbdi vm");
    QBDI::GPRState* gprState = vm->getGPRState();
    if (!gprState) {
      log_.error("failed to get gpr state from qbdi vm - null pointer returned");
      delete vm;
      qbdi_vm_ = nullptr;
      return false;
    }

    log_.verbose("gpr state retrieved successfully", redlog::field("gpr_state_ptr", gprState));

    // allocate virtual stack
    log_.debug("allocating virtual stack for qbdi execution");
    uint8_t* fakestack = nullptr;
    constexpr size_t STACK_SIZE = 0x100000; // 1MB stack

    bool success = QBDI::allocateVirtualStack(gprState, STACK_SIZE, &fakestack);
    if (!success) {
      log_.error("failed to allocate virtual stack", redlog::field("requested", STACK_SIZE));
      delete vm;
      qbdi_vm_ = nullptr;
      return false;
    }

    log_.info(
        "qbdi vm setup completed successfully", redlog::field("stack_bytes", STACK_SIZE),
        redlog::field("stack_mb", STACK_SIZE / (1024 * 1024)), redlog::field("stack_ptr", fakestack)
    );

    // log qbdi version and configuration info
    log_.verbose(
        "qbdi configuration", redlog::field("version", QBDI::getVersion(nullptr)),
        redlog::field("architecture", "x86_64")
    ); // assuming x86_64 for now

    return true;

  } catch (const std::exception& e) {
    log_.error(
        "qbdi vm setup failed with exception", redlog::field("error", e.what()),
        redlog::field("exception_type", typeid(e).name())
    );

    // cleanup on failure
    if (qbdi_vm_) {
      delete static_cast<QBDI::VM*>(qbdi_vm_);
      qbdi_vm_ = nullptr;
    }

    return false;
  } catch (...) {
    log_.error("qbdi vm setup failed with unknown exception");

    // cleanup on failure
    if (qbdi_vm_) {
      delete static_cast<QBDI::VM*>(qbdi_vm_);
      qbdi_vm_ = nullptr;
    }

    return false;
  }
}

bool w1cov_tracer::register_callbacks() {
  if (!qbdi_vm_) {
    log_.error("qbdi vm not initialized - cannot register callbacks");
    return false;
  }

  log_.info("registering qbdi callbacks for coverage collection");

  try {
    auto* vm = static_cast<QBDI::VM*>(qbdi_vm_);

    // register basic block callback
    log_.debug("registering basic block entry callback");
    uint32_t bb_cb_id = vm->addVMEventCB(
        QBDI::VMEvent::BASIC_BLOCK_ENTRY, reinterpret_cast<QBDI::VMCallback>(basic_block_callback), this
    );

    if (bb_cb_id == QBDI::INVALID_EVENTID) {
      log_.error("failed to register basic block callback - invalid event id returned");
      return false;
    }

    log_.info(
        "basic block callback registered successfully", redlog::field("callback_id", bb_cb_id),
        redlog::field("event_type", "BASIC_BLOCK_ENTRY")
    );

    // optionally register instruction callback for more detailed tracing
    redlog::level current_level = redlog::get_level();
    bool enable_instruction_tracing = (current_level <= redlog::level::trace);

    log_.debug(
        "checking if instruction-level tracing should be enabled",
        redlog::field("log_level", redlog::level_name(current_level)),
        redlog::field("enable_tracing", enable_instruction_tracing)
    );

    if (enable_instruction_tracing) {
      log_.debug("registering instruction-level callback for detailed tracing");

      uint32_t inst_cb_id =
          vm->addCodeCB(QBDI::PREINST, reinterpret_cast<QBDI::InstCallback>(instruction_callback), this);

      if (inst_cb_id != QBDI::INVALID_EVENTID) {
        log_.info(
            "instruction callback registered successfully", redlog::field("callback_id", inst_cb_id),
            redlog::field("event_type", "PREINST")
        );
      } else {
        log_.warn("failed to register instruction callback", redlog::field("callback_id", inst_cb_id));
      }
    } else {
      log_.debug("instruction-level tracing disabled", redlog::field("reason", "log level too high"));
    }

    // log callback configuration summary
    log_.verbose(
        "qbdi callback registration completed", redlog::field("bb_callback_id", bb_cb_id),
        redlog::field("instruction_tracing", enable_instruction_tracing)
    );

    return true;

  } catch (const std::exception& e) {
    log_.error(
        "callback registration failed with exception", redlog::field("error", e.what()),
        redlog::field("exception_type", typeid(e).name())
    );
    return false;
  } catch (...) {
    log_.error("callback registration failed with unknown exception");
    return false;
  }
}

void w1cov_tracer::cleanup_qbdi_vm() {
  if (qbdi_vm_) {
    log_.info("cleaning up qbdi vm resources");

    try {
      auto* vm = static_cast<QBDI::VM*>(qbdi_vm_);

      // log vm state before cleanup
      log_.debug("qbdi vm cleanup starting", redlog::field("vm_ptr", vm));

      // delete the QBDI VM instance
      delete vm;
      qbdi_vm_ = nullptr;

      log_.debug("qbdi vm cleanup completed successfully");

    } catch (const std::exception& e) {
      log_.error(
          "error during qbdi vm cleanup", redlog::field("error", e.what()),
          redlog::field("exception_type", typeid(e).name())
      );

      // force null the pointer even if cleanup failed
      qbdi_vm_ = nullptr;

    } catch (...) {
      log_.error("unknown error during qbdi vm cleanup");

      // force null the pointer even if cleanup failed
      qbdi_vm_ = nullptr;
    }
  } else {
    log_.trace("qbdi vm cleanup skipped - no vm instance to clean");
  }
}

QBDIVMAction w1cov_tracer::basic_block_callback(
    QBDIVMPtr vm, QBDIVMStatePtr vmState, QBDIGPRStatePtr gprState, QBDIFPRStatePtr fprState, void* data
) {

  auto* tracer = static_cast<w1cov_tracer*>(data);
  if (!tracer || !vmState) {
    return static_cast<QBDIVMAction>(QBDI::VMAction::CONTINUE);
  }

  try {
    // cast back to QBDI types
    const QBDI::VMState* state = static_cast<const QBDI::VMState*>(vmState);

    // get basic block info
    uint64_t bb_start = state->basicBlockStart;
    uint16_t bb_size = static_cast<uint16_t>(state->basicBlockEnd - state->basicBlockStart);

    tracer->handle_basic_block_entry(bb_start, bb_size);

  } catch (const std::exception& e) {
    tracer->log_.error("error in basic block callback", redlog::field("error", e.what()));
  }

  return static_cast<QBDIVMAction>(QBDI::VMAction::CONTINUE);
}

QBDIVMAction w1cov_tracer::instruction_callback(
    QBDIVMPtr vm, QBDIGPRStatePtr gprState, QBDIFPRStatePtr fprState, void* data
) {

  auto* tracer = static_cast<w1cov_tracer*>(data);
  if (!tracer || !vm) {
    return static_cast<QBDIVMAction>(QBDI::VMAction::CONTINUE);
  }

  try {
    QBDI::VM* qbdi_vm = static_cast<QBDI::VM*>(vm);
    const QBDI::InstAnalysis* analysis = qbdi_vm->getInstAnalysis();
    if (analysis) {
      tracer->handle_instruction_execution(analysis->address);
    }
  } catch (const std::exception& e) {
    tracer->log_.trace("error in instruction callback", redlog::field("error", e.what()));
  }

  return static_cast<QBDIVMAction>(QBDI::VMAction::CONTINUE);
}

void w1cov_tracer::handle_basic_block_entry(uint64_t address, uint16_t size) {
  // increment callback counter for performance monitoring
  uint64_t current_count = callback_count_.fetch_add(1) + 1;

  if (collector_) {
    collector_->record_basic_block(address, size);
  }

  // periodic performance logging (every 10000 callbacks)
  if (current_count % 10000 == 0) {
    auto now = std::chrono::steady_clock::now();
    uint64_t current_time = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    uint64_t time_since_start = current_time - instrumentation_start_time_;
    uint64_t time_since_last = current_time - last_stats_time_;

    if (time_since_start > 0) {
      double total_rate = (current_count * 1000.0) / time_since_start;
      double recent_rate = time_since_last > 0 ? (10000.0 * 1000.0) / time_since_last : 0.0;

      log_.verbose(
          "coverage collection performance", redlog::field("callbacks", current_count),
          redlog::field("elapsed_ms", time_since_start), redlog::field("avg_rate", total_rate),
          redlog::field("recent_rate", recent_rate),
          redlog::field("unique_blocks", collector_ ? collector_->get_unique_blocks() : 0)
      );

      last_stats_time_ = current_time;
    }
  }
}

void w1cov_tracer::handle_instruction_execution(uint64_t address) {
  // detailed instruction-level tracing (optional)
  log_.trace("instruction executed", redlog::field("address", address));
}

bool w1cov_tracer::discover_and_register_modules() {
  if (!mapper_) {
    log_.error("module mapper not initialized");
    return false;
  }

  log_.info("discovering process modules");

  // try qbdi-based discovery first
  if (!mapper_->discover_qbdi_modules()) {
    log_.warn("qbdi module discovery failed, trying process-based discovery");

    if (!mapper_->discover_process_modules()) {
      log_.error("all module discovery methods failed");
      return false;
    }
  }

  // register discovered modules with collector
  size_t registered_count = mapper_->register_discovered_modules();

  log_.info(
      "module discovery completed", redlog::field("total_regions", mapper_->get_total_regions()),
      redlog::field("executable_regions", mapper_->get_executable_count()),
      redlog::field("user_modules", mapper_->get_user_module_count()), redlog::field("registered", registered_count)
  );

  return registered_count > 0;
}

bool w1cov_tracer::setup_instrumentation_ranges() {
  if (!qbdi_vm_) {
    log_.error("qbdi vm not initialized - cannot setup instrumentation ranges");
    return false;
  }

  if (!mapper_) {
    log_.error("module mapper not initialized - cannot setup instrumentation ranges");
    return false;
  }

  log_.info("setting up qbdi instrumentation ranges for coverage collection");

  try {
    auto* vm = static_cast<QBDI::VM*>(qbdi_vm_);

    // get user modules to instrument
    log_.debug("retrieving user modules for instrumentation");
    auto user_modules = mapper_->get_user_modules();
    auto all_executable = mapper_->get_executable_regions();

    log_.verbose(
        "module analysis for instrumentation", redlog::field("executable_regions", all_executable.size()),
        redlog::field("user_modules", user_modules.size()),
        redlog::field("system_modules", all_executable.size() - user_modules.size())
    );

    if (user_modules.empty()) {
      log_.warn(
          "no user modules found for targeted instrumentation",
          redlog::field("executable_regions", all_executable.size())
      );

      // log some examples of what was excluded
      if (!all_executable.empty()) {
        log_.debug("examples of excluded modules");
        size_t example_count = (std::min) (static_cast<size_t>(5), all_executable.size());
        for (size_t i = 0; i < example_count; ++i) {
          const auto& region = all_executable[i];
          log_.verbose(
              "excluded module example", redlog::field("name", region.name), redlog::field("start", region.start),
              redlog::field("size", region.size()), redlog::field("reason", "system_module")
          );
        }
      }

      // fallback: instrument all executable regions
      log_.info("falling back to instrumenting all executable regions");
      vm->instrumentAllExecutableMaps();

      log_.info("instrumented all executable regions as fallback", redlog::field("regions", all_executable.size()));

      return true;
    }

    // instrument specific modules
    uint64_t total_instrumented_bytes = 0;
    size_t successful_ranges = 0;
    size_t failed_ranges = 0;

    log_.debug("adding specific instrumentation ranges for user modules");

    for (const auto& region : user_modules) {
      try {
        QBDI::rword start_addr = static_cast<QBDI::rword>(region.start);
        QBDI::rword end_addr = static_cast<QBDI::rword>(region.end);

        // validate range before adding
        if (start_addr >= end_addr) {
          log_.warn(
              "invalid address range detected", redlog::field("start", region.start), redlog::field("end", region.end),
              redlog::field("name", region.name)
          );
          failed_ranges++;
          continue;
        }

        vm->addInstrumentedRange(start_addr, end_addr);

        uint64_t range_size = region.end - region.start;
        total_instrumented_bytes += range_size;
        successful_ranges++;

        log_.verbose(
            "added instrumentation range", redlog::field("start", region.start), redlog::field("end", region.end),
            redlog::field("bytes", range_size), redlog::field("kb", range_size / 1024),
            redlog::field("name", region.name), redlog::field("perms", region.permission)
        );

      } catch (const std::exception& e) {
        log_.error(
            "failed to add instrumentation range", redlog::field("start", region.start),
            redlog::field("end", region.end), redlog::field("name", region.name), redlog::field("error", e.what())
        );
        failed_ranges++;
      }
    }

    log_.info(
        "instrumentation ranges configuration completed", redlog::field("modules", user_modules.size()),
        redlog::field("successful", successful_ranges), redlog::field("failed", failed_ranges),
        redlog::field("bytes", total_instrumented_bytes), redlog::field("mb", total_instrumented_bytes / (1024 * 1024))
    );

    if (successful_ranges == 0) {
      log_.error("no instrumentation ranges were successfully configured");
      return false;
    }

    return true;

  } catch (const std::exception& e) {
    log_.error(
        "failed to setup instrumentation ranges with exception", redlog::field("error", e.what()),
        redlog::field("exception_type", typeid(e).name())
    );
    return false;
  } catch (...) {
    log_.error("failed to setup instrumentation ranges with unknown exception");
    return false;
  }
}

void w1cov_tracer::print_statistics() const {
  if (!collector_) {
    log_.warn("cannot print statistics - collector not initialized");
    return;
  }

  size_t total_blocks = collector_->get_total_blocks();
  size_t unique_blocks = collector_->get_unique_blocks();
  auto coverage_stats = collector_->get_coverage_stats();

  // calculate performance metrics
  uint64_t current_callbacks = callback_count_;
  uint64_t start_time = instrumentation_start_time_;

  auto now = std::chrono::steady_clock::now();
  uint64_t current_time = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
  uint64_t elapsed_time = (start_time > 0) ? (current_time - start_time) : 0;

  double callbacks_per_second = (elapsed_time > 0) ? (current_callbacks * 1000.0) / elapsed_time : 0.0;
  double coverage_efficiency =
      (current_callbacks > 0) ? (static_cast<double>(unique_blocks) / current_callbacks) * 100.0 : 0.0;

  log_.info(
      "coverage collection statistics", redlog::field("total_blocks", total_blocks),
      redlog::field("unique_blocks", unique_blocks), redlog::field("modules", coverage_stats.size()),
      redlog::field("callbacks", current_callbacks), redlog::field("elapsed_ms", elapsed_time),
      redlog::field("rate", callbacks_per_second), redlog::field("efficiency_pct", coverage_efficiency)
  );

  // log memory usage estimation
  size_t estimated_memory = (total_blocks * sizeof(void*)) + (coverage_stats.size() * 64);
  log_.verbose(
      "coverage memory usage estimation", redlog::field("bytes", estimated_memory),
      redlog::field("kb", estimated_memory / 1024)
  );

  // log per-module statistics
  size_t modules_logged = 0;
  for (const auto& [module_id, block_count] : coverage_stats) {
    if (modules_logged < 10) { // limit verbose output
      log_.verbose("module coverage", redlog::field("module_id", module_id), redlog::field("blocks", block_count));
      modules_logged++;
    } else if (modules_logged == 10) {
      log_.verbose("additional modules with coverage", redlog::field("remaining_modules", coverage_stats.size() - 10));
      break;
    }
  }

  // performance warnings
  if (callbacks_per_second > 0 && callbacks_per_second < 1000) {
    log_.warn("low callback processing rate detected", redlog::field("rate", callbacks_per_second));
  }

  if (coverage_efficiency < 10.0 && current_callbacks > 1000) {
    log_.warn(
        "low coverage efficiency detected - many duplicate blocks",
        redlog::field("efficiency_pct", coverage_efficiency),
        redlog::field("suggestion", "consider excluding system modules")
    );
  }
}

bool w1cov_tracer::export_coverage_data() const {
  if (!collector_) {
    log_.error("collector not initialized");
    return false;
  }

  log_.info("exporting coverage data", redlog::field("output_file", output_file_));

  return collector_->write_drcov_file(output_file_);
}

size_t w1cov_tracer::get_basic_block_count() const { return collector_ ? collector_->get_total_blocks() : 0; }

size_t w1cov_tracer::get_module_count() const { return mapper_ ? mapper_->get_total_regions() : 0; }

std::string w1cov_tracer::get_env_var(const char* name, const std::string& default_value) const {
  const char* value = std::getenv(name);
  return value ? std::string(value) : default_value;
}

bool w1cov_tracer::get_env_bool(const char* name, bool default_value) const {
  const char* value = std::getenv(name);
  if (!value) {
    return default_value;
  }

  std::string str_value(value);
  std::transform(str_value.begin(), str_value.end(), str_value.begin(), ::tolower);

  return str_value == "1" || str_value == "true" || str_value == "yes" || str_value == "on";
}

// global instance
static w1cov_tracer g_tracer;

w1cov_tracer& get_global_tracer() { return g_tracer; }

// library constructor/destructor
extern "C" {

void w1cov_initialize() {
  auto& tracer = get_global_tracer();

  // check if w1cov is enabled
  const char* enabled = std::getenv("W1COV_ENABLED");
  if (!enabled || std::strcmp(enabled, "1") != 0) {
    return; // not enabled
  }

  if (tracer.initialize()) {
    tracer.start_instrumentation();
  }
}

void w1cov_finalize() {
  auto& tracer = get_global_tracer();
  tracer.shutdown();
}

#ifdef _WIN32
// Windows DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
  switch (ul_reason_for_call) {
  case DLL_PROCESS_ATTACH:
    // Initialize coverage system
    w1cov_initialize();
    break;

  case DLL_PROCESS_DETACH:
    // Cleanup and export coverage
    w1cov_finalize();
    break;

  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
    break;
  }
  return TRUE;
}
#endif

} // extern "C"

} // namespace w1::coverage