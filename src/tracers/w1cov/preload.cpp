#include <cstdlib>
#include <memory>

#include "QBDIPreload.h"
#include <redlog/redlog.hpp>

#include <w1tn3ss/engine/tracer_engine.hpp>
#include <w1tn3ss/util/env_config.hpp>

#include "coverage_config.hpp"
#include "coverage_tracer.hpp"

// globals
static std::unique_ptr<w1cov::coverage_tracer> g_tracer;
static std::unique_ptr<w1::tracer_engine<w1cov::coverage_tracer>> g_engine;

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  auto log = redlog::get_logger("w1cov.preload");

  log.inf("qbdipreload_on_run called");

  // get config
  w1::util::env_config config_loader("W1COV_");
  w1cov::coverage_config config;

  int debug_level = config_loader.get<int>("VERBOSE", 0);

  config.output_file = config_loader.get<std::string>("OUTPUT_FILE", config.output_file);
  config.exclude_system_modules = config_loader.get<bool>("EXCLUDE_SYSTEM", config.exclude_system_modules);
  config.track_hitcounts = config_loader.get<bool>("TRACK_HITCOUNTS", config.track_hitcounts);
  auto target_modules_env = config_loader.get_list("MODULE_FILTER");
  if (!target_modules_env.empty()) {
    config.module_filter = target_modules_env;
  }

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

  // create tracer
  log.inf("creating tracer");
  g_tracer = std::make_unique<w1cov::coverage_tracer>(config);

  // create engine
  log.inf("creating tracer engine");
  g_engine = std::make_unique<w1::tracer_engine<w1cov::coverage_tracer>>(vm, *g_tracer);

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
    g_tracer->shutdown();
    g_tracer.reset();
  }

  if (g_engine) {
    g_engine.reset();
  }

  log.inf("qbdipreload_on_exit completed");
  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_start(void* main) { return QBDIPRELOAD_NOT_HANDLED; }

QBDI_EXPORT int qbdipreload_on_premain(void* gprCtx, void* fpuCtx) { return QBDIPRELOAD_NOT_HANDLED; }

QBDI_EXPORT int qbdipreload_on_main(int argc, char** argv) { return QBDIPRELOAD_NOT_HANDLED; }

} // extern "C"