#include <cstring>
#include <memory>

#include "QBDIPreload.h"
#include <redlog.hpp>

#include <w1tn3ss/engine/tracer_engine.hpp>
#include <w1tn3ss/util/env_config.hpp>
#include <w1tn3ss/util/signal_handler.hpp>
#include <w1tn3ss/util/stderr_write.hpp>

#include "script_config.hpp"
#include "script_tracer.hpp"

// globals
static std::unique_ptr<w1::tracers::script::script_tracer> g_tracer;
static std::unique_ptr<w1::tracer_engine<w1::tracers::script::script_tracer>> g_engine;
static w1::tracers::script::config g_config;

namespace {

/**
 * @brief shutdown script tracer with signal-safe error handling
 */
void shutdown_script() {
  if (!g_tracer) {
    return;
  }

  try {
    g_tracer->shutdown();
  } catch (...) {
    // signal-safe error reporting
    const char* error_msg = "w1script: shutdown failed\n";
    w1::util::stderr_write(error_msg);
  }
}

} // anonymous namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  auto logger = redlog::get_logger("w1.script_preload");

  logger.inf("qbdipreload_on_run called");

  // get config
  g_config = w1::tracers::script::config::from_environment();

  if (!g_config.is_valid()) {
    logger.err("invalid configuration - W1SCRIPT_SCRIPT must be specified");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  w1::util::env_config config_loader("W1SCRIPT_");
  int debug_level = config_loader.get<int>("VERBOSE", 0);

  // set log level based on debug level
  if (debug_level >= 4) {
    redlog::set_level(redlog::level::pedantic);
  } else if (debug_level >= 3) {
    redlog::set_level(redlog::level::debug);
  } else if (debug_level >= 2) {
    redlog::set_level(redlog::level::trace);
  } else if (debug_level >= 1) {
    redlog::set_level(redlog::level::verbose);
  } else {
    redlog::set_level(redlog::level::info);
  }

  // initialize signal handling for emergency shutdown
  w1::tn3ss::signal_handler::config sig_config;
  sig_config.context_name = "w1script";
  sig_config.log_signals = (debug_level >= 1);

  if (w1::tn3ss::signal_handler::initialize(sig_config)) {
    w1::tn3ss::signal_handler::register_cleanup(
        shutdown_script,
        200, // high priority
        "w1script_shutdown"
    );
    logger.inf("signal handling initialized for script shutdown");
  } else {
    logger.wrn("failed to initialize signal handling - script shutdown on signal unavailable");
  }

  // create tracer
  logger.inf("creating script tracer");
  g_tracer = std::make_unique<w1::tracers::script::script_tracer>();

  // create engine
  logger.inf("creating tracer engine");
  g_engine = std::make_unique<w1::tracer_engine<w1::tracers::script::script_tracer>>(vm, *g_tracer, g_config);

  // initialize tracer
  if (!g_tracer->initialize(*g_engine)) {
    logger.err("script tracer initialization failed");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  // instrument
  logger.inf("instrumenting engine");
  if (!g_engine->instrument()) {
    logger.err("engine instrumentation failed");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  logger.inf("engine instrumentation successful");

  // run engine
  logger.inf("running engine", redlog::field("start", "0x%08x", start), redlog::field("stop", "0x%08x", stop));
  if (!g_engine->run(start, stop)) {
    logger.err("engine run failed");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  // execution doesn't reach here if it works (vm run jumps)
  logger.inf("qbdipreload_on_run completed");

  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_exit(int status) {
  auto logger = redlog::get_logger("w1.script_preload");

  logger.inf("qbdipreload_on_exit called", redlog::field("status", status));

  if (g_tracer) {
    logger.inf("shutting down script tracer");

    shutdown_script();

    logger.inf("script tracer shutdown completed");

    g_tracer.reset();
  }

  if (g_engine) {
    g_engine.reset();
  }

  logger.inf("qbdipreload_on_exit completed");
  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_start(void* main) { return QBDIPRELOAD_NOT_HANDLED; }

QBDI_EXPORT int qbdipreload_on_premain(void* gprCtx, void* fpuCtx) { return QBDIPRELOAD_NOT_HANDLED; }

QBDI_EXPORT int qbdipreload_on_main(int argc, char** argv) { return QBDIPRELOAD_NOT_HANDLED; }

} // extern "C"