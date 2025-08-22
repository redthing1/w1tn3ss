#include <cstring>
#include <memory>

#include "QBDIPreload.h"
#include <redlog.hpp>

#include <w1tn3ss/engine/tracer_engine.hpp>
#include <w1tn3ss/util/env_config.hpp>
#include <w1tn3ss/util/signal_handler.hpp>
#include <w1tn3ss/util/stderr_write.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1common/windows_console.hpp>
#endif

#include "trace_config.hpp"
#include "trace_tracer.hpp"

// globals
static std::unique_ptr<w1trace::trace_tracer> g_tracer;
static std::unique_ptr<w1::tracer_engine<w1trace::trace_tracer>> g_engine;
static w1trace::trace_config g_config;

namespace {

/**
 * @brief export trace data with signal-safe error handling
 */
void export_trace() {
  if (!g_tracer) {
    return;
  }

  try {
    // shutdown collector to ensure all data is written
    g_tracer->get_collector().shutdown();
  } catch (...) {
    // signal-safe error reporting
    const char* error_msg = "w1trace: trace export failed\n";
    w1::util::stderr_write(error_msg);
  }
}

} // anonymous namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  auto log = redlog::get_logger("w1trace.preload");

  log.inf("qbdipreload_on_run called");

  // get config
  g_config = w1trace::trace_config::from_environment();

  w1::util::env_config config_loader("W1TRACE_");
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

  // initialize signal handling for emergency trace export
  w1::tn3ss::signal_handler::config sig_config;
  sig_config.context_name = "w1trace";
  sig_config.log_signals = (debug_level >= 1);

  if (w1::tn3ss::signal_handler::initialize(sig_config)) {
    w1::tn3ss::signal_handler::register_cleanup(
        export_trace,
        200, // high priority
        "w1trace_export"
    );
    log.inf("signal handling initialized for trace export");
  } else {
    log.wrn("failed to initialize signal handling - trace export on signal unavailable");
  }

  // create tracer
  log.inf("creating tracer");
  g_tracer = std::make_unique<w1trace::trace_tracer>(g_config);

  // create engine
  log.inf("creating tracer engine");
  g_engine = std::make_unique<w1::tracer_engine<w1trace::trace_tracer>>(vm, *g_tracer, g_config);

  // initialize tracer
  if (!g_tracer->initialize(*g_engine)) {
    log.err("tracer initialization failed");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  // instrument
  log.inf("instrumenting engine");
  if (!g_engine->instrument()) {
    log.err("engine instrumentation failed");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  log.inf("engine instrumentation successful");

  // run engine
  log.inf("running engine", redlog::field("start", "0x%08x", start), redlog::field("stop", "0x%08x", stop));
  if (!g_engine->run(start, stop)) {
    log.err("engine run failed");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  // execution doesn't reach here if it works (vm run jumps)
  log.inf("qbdipreload_on_run completed");

  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_exit(int status) {
  auto log = redlog::get_logger("w1trace.preload");

  log.inf("qbdipreload_on_exit called", redlog::field("status", status));

  if (g_tracer) {
    log.inf("shutting down tracer and exporting trace");

    export_trace();

    log.inf("trace data export completed", redlog::field("output_file", g_config.output_file));

    g_tracer->shutdown();
    g_tracer.reset();
  }

  if (g_engine) {
    g_engine.reset();
  }

  log.inf("qbdipreload_on_exit completed");
  return QBDIPRELOAD_NO_ERROR;
}

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