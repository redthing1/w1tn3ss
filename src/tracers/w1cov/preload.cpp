#include <cstdlib>
#include <cstring>
#include <memory>

#include "QBDIPreload.h"
#include <redlog.hpp>

#include <w1tn3ss/engine/tracer_engine.hpp>
#include <w1tn3ss/util/env_config.hpp>
#include <w1tn3ss/util/signal_handler.hpp>
#include <w1tn3ss/util/stderr_write.hpp>
#include <w1tn3ss/formats/drcov.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1common/windows_console.hpp>
#endif

#include "coverage_config.hpp"
#include "coverage_tracer.hpp"

// globals
static std::unique_ptr<w1cov::coverage_tracer> g_tracer;
static std::unique_ptr<w1::tracer_engine<w1cov::coverage_tracer>> g_engine;
static w1cov::coverage_config g_config;

namespace {

/**
 * @brief export coverage data with signal-safe error handling
 */
void export_coverage() {
  if (!g_tracer) {
    return;
  }

  try {
    auto data = g_tracer->get_collector().build_drcov_data();
    if (!data.basic_blocks.empty()) {
      drcov::write(g_config.output_file, data);
    }
  } catch (...) {
    // signal-safe error reporting
    const char* error_msg = "w1cov: coverage export failed\n";
    w1::util::stderr_write(error_msg);
  }
}

} // anonymous namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  auto log = redlog::get_logger("w1cov.preload");

  log.inf("qbdipreload_on_run called");

  // get config
  g_config = w1cov::coverage_config::from_environment();

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

  // initialize signal handling for emergency coverage export
  w1::tn3ss::signal_handler::config sig_config;
  sig_config.context_name = "w1cov";
  sig_config.log_signals = (g_config.verbose >= 1);

  if (w1::tn3ss::signal_handler::initialize(sig_config)) {
    w1::tn3ss::signal_handler::register_cleanup(
        export_coverage,
        200, // high priority
        "w1cov_export"
    );
    log.inf("signal handling initialized for coverage export");
  } else {
    log.wrn("failed to initialize signal handling - coverage export on signal unavailable");
  }

  // create tracer
  log.inf("creating tracer");
  g_tracer = std::make_unique<w1cov::coverage_tracer>(g_config);

  // create engine
  log.inf("creating tracer engine");
  g_engine = std::make_unique<w1::tracer_engine<w1cov::coverage_tracer>>(vm, *g_tracer, g_config);

  // initialize tracer
  g_tracer->initialize(*g_engine);

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
  auto log = redlog::get_logger("w1cov.preload");

  log.inf("qbdipreload_on_exit called", redlog::field("status", status));

  if (g_tracer) {
    log.inf("shutting down tracer and exporting coverage");

    export_coverage();
    auto data = g_tracer->get_collector().build_drcov_data();
    if (!data.basic_blocks.empty()) {
      log.inf("coverage data export completed", redlog::field("output_file", g_config.output_file));
    } else {
      log.wrn("no basic blocks collected, skipping export");
    }

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