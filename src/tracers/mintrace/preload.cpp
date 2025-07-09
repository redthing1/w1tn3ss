#include <cstdlib>
#include <cstring>
#include <memory>

#include "QBDIPreload.h"
#include <redlog.hpp>

#include <w1tn3ss/engine/tracer_engine.hpp>
#include <w1tn3ss/util/env_config.hpp>
#include <w1tn3ss/util/module_range_index.hpp>
#include <w1tn3ss/util/module_scanner.hpp>
#include <w1tn3ss/util/signal_handler.hpp>
#include <w1tn3ss/util/stderr_write.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1common/windows_console.hpp>
#endif

class mintrace_tracer {
public:
  explicit mintrace_tracer() { log_.inf("tracer created"); }

  bool initialize(w1::tracer_engine<mintrace_tracer>& engine) {
    log_.inf("initialize called");

    // scan and index modules
    log_.inf("scanning modules");
    auto modules = scanner_.scan_executable_modules();
    index_.rebuild_from_modules(std::move(modules));

    log_.inf("module indexing complete", redlog::field("modules", index_.size()));

    return true;
  }

  void shutdown() { log_.inf("shutdown called"); }

  const char* get_name() const { return "mintrace"; }

  QBDI::VMAction on_instruction_preinst(QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) {
    const QBDI::InstAnalysis* analysis = vm->getInstAnalysis();

    if (analysis) {
      log_.trc(
          "instruction", redlog::field("address", "0x%08x", analysis->address),
          redlog::field("disassembly", analysis->disassembly)
      );
    } else {
      log_.error("instruction analysis failed");
    }

    return QBDI::VMAction::CONTINUE;
  }

  QBDI::VMAction on_basic_block_entry(
      QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
  ) {
    QBDI::rword block_start = state->basicBlockStart;
    QBDI::rword block_size = state->basicBlockEnd - state->basicBlockStart;

    log_.trc("basic block entry", redlog::field("start", "0x%08x", block_start), redlog::field("size", block_size));

    return QBDI::VMAction::CONTINUE;
  }

private:
  redlog::logger log_ = redlog::get_logger("mintrace.tracer");
  w1::util::module_scanner scanner_;
  w1::util::module_range_index index_;
};

// globals
static std::unique_ptr<mintrace_tracer> g_tracer;
static std::unique_ptr<w1::tracer_engine<mintrace_tracer>> g_engine;

namespace {

/**
 * @brief shutdown tracer with signal-safe error handling
 */
void shutdown_tracer() {
  if (!g_tracer) {
    return;
  }

  try {
    g_tracer->shutdown();
  } catch (...) {
    const char* error_msg = "mintrace: tracer shutdown failed\n";
    w1::util::stderr_write(error_msg);
  }
}

} // anonymous namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  auto log = redlog::get_logger("mintrace.preload");

  log.inf("qbdipreload_on_run called");

  // get config
  w1::util::env_config config_loader("MINTRACE_");
  int verbose = config_loader.get<int>("VERBOSE", 0);

  // set log level based on debug level
  if (verbose >= 4) {
    redlog::set_level(redlog::level::pedantic);
  } else if (verbose >= 3) {
    redlog::set_level(redlog::level::debug);
  } else if (verbose >= 2) {
    redlog::set_level(redlog::level::trace);
  } else if (verbose >= 1) {
    redlog::set_level(redlog::level::verbose);
  } else {
    redlog::set_level(redlog::level::info);
  }

  // initialize signal handling for emergency shutdown
  w1::tn3ss::signal_handler::config sig_config;
  sig_config.context_name = "mintrace";
  sig_config.log_signals = verbose;

  if (w1::tn3ss::signal_handler::initialize(sig_config)) {
    w1::tn3ss::signal_handler::register_cleanup(
        shutdown_tracer,
        200, // high priority
        "mintrace_shutdown"
    );
    log.inf("signal handling initialized for tracer shutdown");
  } else {
    log.wrn("failed to initialize signal handling - shutdown on signal unavailable");
  }

  // create tracer
  log.inf("creating tracer");
  g_tracer = std::make_unique<mintrace_tracer>();

  // create engine
  log.inf("creating tracer engine");
  g_engine = std::make_unique<w1::tracer_engine<mintrace_tracer>>(vm, *g_tracer);

  // initialize tracer
  g_tracer->initialize(*g_engine);

  // instrument
  log.inf("instrumenting engine");
  if (!g_engine->instrument()) {
    log.error("engine instrumentation failed");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  log.inf("engine instrumentation successful");

  // run engine
  log.inf("running engine", redlog::field("start", "0x%08x", start), redlog::field("stop", "0x%08x", stop));
  if (!g_engine->run(start, stop)) {
    log.error("engine run failed");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  // execution doesn't reach here if it works (vm run jumps)
  log.inf("qbdipreload_on_run completed");

  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_exit(int status) { return QBDIPRELOAD_NO_ERROR; }

QBDI_EXPORT int qbdipreload_on_start(void* main) {
#if defined(_WIN32) || defined(WIN32)
  // on windows, allow logging to show for gui targets
  w1::common::allocate_windows_console();
#endif
  return QBDIPRELOAD_NOT_HANDLED;
}

QBDI_EXPORT int qbdipreload_on_premain(void* gprCtx, void* fpuCtx) { return QBDIPRELOAD_NOT_HANDLED; }

QBDI_EXPORT int qbdipreload_on_main(int argc, char** argv) { return QBDIPRELOAD_NOT_HANDLED; }

} // extern "C"