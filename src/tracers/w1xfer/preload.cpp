#include <cstring>
#include <memory>
#include <unistd.h>

#include "QBDIPreload.h"
#include <redlog.hpp>
#include <w1tn3ss/engine/tracer_engine.hpp>
#include <w1tn3ss/util/signal_handler.hpp>

#include "transfer_config.hpp"
#include "transfer_tracer.hpp"

// globals
static std::unique_ptr<w1xfer::transfer_tracer> g_tracer;
static std::unique_ptr<w1::tracer_engine<w1xfer::transfer_tracer>> g_engine;

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
    const char* error_msg = "w1xfer: tracer shutdown failed\n";
    write(STDERR_FILENO, error_msg, strlen(error_msg));
  }
}

} // anonymous namespace

extern "C" {

QBDIPRELOAD_INIT;

static auto logger = redlog::get_logger("w1.preload");

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {

  logger.inf("w1xfer preload starting");

  // get config from environment
  try {
    w1xfer::transfer_config config = w1xfer::transfer_config::from_environment();

    // set log level based on debug level
    if (config.verbose >= 4) {
      redlog::set_level(redlog::level::pedantic);
    } else if (config.verbose >= 3) {
      redlog::set_level(redlog::level::debug);
    } else if (config.verbose >= 2) {
      redlog::set_level(redlog::level::trace);
    } else if (config.verbose >= 1) {
      redlog::set_level(redlog::level::verbose);
    } else {
      redlog::set_level(redlog::level::info);
    }

    // initialize signal handling for emergency shutdown
    w1::tn3ss::signal_handler::config sig_config;
    sig_config.context_name = "w1xfer";
    sig_config.log_signals = config.verbose;

    if (w1::tn3ss::signal_handler::initialize(sig_config)) {
      w1::tn3ss::signal_handler::register_cleanup(
          shutdown_tracer,
          200, // high priority
          "w1xfer_shutdown"
      );
      logger.inf("signal handling initialized for tracer shutdown");
    } else {
      logger.wrn("failed to initialize signal handling - shutdown on signal unavailable");
    }

    // create tracer
    logger.inf("creating transfer tracer");
    g_tracer = std::make_unique<w1xfer::transfer_tracer>(config);

    // create engine
    logger.inf("creating tracer engine");
    g_engine = std::make_unique<w1::tracer_engine<w1xfer::transfer_tracer>>(vm, *g_tracer);

    // initialize tracer
    if (!g_tracer->initialize(*g_engine)) {
      logger.err("tracer initialization failed");
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
    logger.inf("running engine", redlog::field("start", "0x%016llx", start), redlog::field("stop", "0x%016llx", stop));
    if (!g_engine->run(start, stop)) {
      logger.err("engine run failed");
      return QBDIPRELOAD_ERR_STARTUP_FAILED;
    }

    // execution doesn't reach here if it works (vm run jumps)
    logger.inf("w1xfer preload completed");

  } catch (const std::exception& e) {
    logger.err("failed to initialize w1xfer tracer", redlog::field("error", e.what()));
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_exit(int status) {
  logger.inf("w1xfer preload exit", redlog::field("status", status));

  if (g_tracer) {
    g_tracer->shutdown();
  }

  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_start(void* main) { return QBDIPRELOAD_NOT_HANDLED; }

QBDI_EXPORT int qbdipreload_on_premain(void* gprCtx, void* fpuCtx) { return QBDIPRELOAD_NOT_HANDLED; }

QBDI_EXPORT int qbdipreload_on_main(int argc, char** argv) { return QBDIPRELOAD_NOT_HANDLED; }

} // extern "C"