#include <cstring>
#include <memory>
#include <unistd.h>

#include "QBDIPreload.h"
#include <redlog.hpp>

#include <w1tn3ss/engine/tracer_engine.hpp>
#include <w1tn3ss/util/signal_handler.hpp>
#include "memory_tracer.hpp"
#include "memory_config.hpp"

// globals
static std::unique_ptr<w1mem::memory_tracer> g_tracer;
static std::unique_ptr<w1::tracer_engine<w1mem::memory_tracer>> g_engine;

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
    const char* error_msg = "w1mem: tracer shutdown failed\n";
    write(STDERR_FILENO, error_msg, strlen(error_msg));
  }
}

} // anonymous namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  auto log = redlog::get_logger("w1mem.preload");

  log.inf("w1mem preload starting");

  // get config from environment
  w1mem::memory_config config = w1mem::memory_config::from_environment();

  if (config.verbose) {
    redlog::set_level(redlog::level::debug);
  }

  // initialize signal handling for emergency shutdown
  w1::tn3ss::signal_handler::config sig_config;
  sig_config.context_name = "w1mem";
  sig_config.log_signals = config.verbose;

  if (w1::tn3ss::signal_handler::initialize(sig_config)) {
    w1::tn3ss::signal_handler::register_cleanup(
        shutdown_tracer,
        200, // high priority
        "w1mem_shutdown"
    );
    log.inf("signal handling initialized for tracer shutdown");
  } else {
    log.wrn("failed to initialize signal handling - shutdown on signal unavailable");
  }

  // create tracer
  log.inf("creating memory tracer");
  g_tracer = std::make_unique<w1mem::memory_tracer>(config);

  // create engine
  log.inf("creating tracer engine");
  g_engine = std::make_unique<w1::tracer_engine<w1mem::memory_tracer>>(vm, *g_tracer);

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
  log.inf("w1mem preload completed");

  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_exit(int status) {
  auto log = redlog::get_logger("w1mem.preload");
  log.inf("w1mem preload exit", redlog::field("status", status));

  if (g_tracer) {
    g_tracer->shutdown();
  }

  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_start(void* main) { return QBDIPRELOAD_NOT_HANDLED; }

QBDI_EXPORT int qbdipreload_on_premain(void* gprCtx, void* fpuCtx) { return QBDIPRELOAD_NOT_HANDLED; }

QBDI_EXPORT int qbdipreload_on_main(int argc, char** argv) { return QBDIPRELOAD_NOT_HANDLED; }

} // extern "C"