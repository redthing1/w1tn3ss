#include <cstring>
#include <memory>

#include "QBDIPreload.h"
#include <redlog.hpp>

#include <w1tn3ss/engine/tracer_engine.hpp>
#include <w1tn3ss/util/signal_handler.hpp>
#include <w1tn3ss/util/stderr_write.hpp>
#include "instruction_tracer.hpp"
#include "instruction_config.hpp"

// globals
static std::unique_ptr<w1inst::instruction_tracer> g_tracer;
static std::unique_ptr<w1::tracer_engine<w1inst::instruction_tracer>> g_engine;
static w1inst::instruction_config g_config;

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
    const char* error_msg = "w1inst: tracer shutdown failed\n";
    w1::util::stderr_write(error_msg);
  }
}

} // anonymous namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  auto log = redlog::get_logger("w1inst.preload");

  log.inf("w1inst preload starting");

  // get config from environment
  try {
    g_config = w1inst::instruction_config::from_environment();

    // set log level based on debug level
    if (g_config.verbose >= 4) {
      redlog::set_level(redlog::level::pedantic);
    } else if (g_config.verbose >= 3) {
      redlog::set_level(redlog::level::debug);
    } else if (g_config.verbose >= 2) {
      redlog::set_level(redlog::level::trace);
    } else if (g_config.verbose >= 1) {
      redlog::set_level(redlog::level::verbose);
    } else {
      redlog::set_level(redlog::level::info);
    }

    // initialize signal handling for emergency shutdown
    w1::tn3ss::signal_handler::config sig_config;
    sig_config.context_name = "w1inst";
    sig_config.log_signals = g_config.verbose;

    if (w1::tn3ss::signal_handler::initialize(sig_config)) {
      w1::tn3ss::signal_handler::register_cleanup(
          shutdown_tracer,
          200, // high priority
          "w1inst_shutdown"
      );
      log.inf("signal handling initialized for tracer shutdown");
    } else {
      log.wrn("failed to initialize signal handling - shutdown on signal unavailable");
    }

    // create tracer
    log.inf("creating instruction tracer");
    g_tracer = std::make_unique<w1inst::instruction_tracer>(g_config);

    // create engine
    log.inf("creating tracer engine");
    g_engine = std::make_unique<w1::tracer_engine<w1inst::instruction_tracer>>(vm, *g_tracer, g_config);

    // initialize tracer
    if (!g_tracer->initialize(*g_engine)) {
      log.error("tracer initialization failed");
      return QBDIPRELOAD_ERR_STARTUP_FAILED;
    }

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
    log.inf("w1inst preload completed");

  } catch (const std::exception& e) {
    log.error("failed to initialize w1inst tracer", redlog::field("error", e.what()));
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_exit(int status) {
  auto log = redlog::get_logger("w1inst.preload");
  log.inf("w1inst preload exit", redlog::field("status", status));

  if (g_tracer) {
    g_tracer->shutdown();
  }

  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_start(void* main) { return QBDIPRELOAD_NOT_HANDLED; }

QBDI_EXPORT int qbdipreload_on_premain(void* gprCtx, void* fpuCtx) { return QBDIPRELOAD_NOT_HANDLED; }

QBDI_EXPORT int qbdipreload_on_main(int argc, char** argv) { return QBDIPRELOAD_NOT_HANDLED; }

} // extern "C"