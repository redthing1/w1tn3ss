#include <cstdlib>
#include <memory>

#include "QBDIPreload.h"
#include <redlog/redlog.hpp>

#include <w1tn3ss/engine/tracer_engine.hpp>
#include <w1tn3ss/util/env_config.hpp>
#include <w1tn3ss/formats/drcov.hpp>

#include "coverage_config.hpp"
#include "coverage_tracer.hpp"

// globals
static std::unique_ptr<w1cov::coverage_tracer> g_tracer;
static std::unique_ptr<w1::tracer_engine<w1cov::coverage_tracer>> g_engine;
static w1cov::coverage_config g_config;

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  auto log = redlog::get_logger("w1cov.preload");

  log.inf("qbdipreload_on_run called");

  // get config
  w1::util::env_config config_loader("W1COV_");

  int debug_level = config_loader.get<int>("VERBOSE", 0);

  g_config.output_file = config_loader.get<std::string>("OUTPUT_FILE", g_config.output_file);
  g_config.exclude_system_modules = config_loader.get<bool>("EXCLUDE_SYSTEM", g_config.exclude_system_modules);
  g_config.track_hitcounts = config_loader.get<bool>("TRACK_HITCOUNTS", g_config.track_hitcounts);
  auto target_modules_env = config_loader.get_list("MODULE_FILTER");
  if (!target_modules_env.empty()) {
    g_config.module_filter = target_modules_env;
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
  g_tracer = std::make_unique<w1cov::coverage_tracer>(g_config);

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

    // export coverage before shutdown
    try {
      auto data = g_tracer->get_collector().build_drcov_data();
      if (!data.basic_blocks.empty()) {
        drcov::write(g_config.output_file, data);
        log.inf("coverage data export completed", redlog::field("output_file", g_config.output_file));
      } else {
        log.wrn("no basic blocks collected, skipping export");
      }
    } catch (const std::exception& e) {
      log.err("exception during coverage export", redlog::field("error", e.what()));
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

QBDI_EXPORT int qbdipreload_on_start(void* main) { return QBDIPRELOAD_NOT_HANDLED; }

QBDI_EXPORT int qbdipreload_on_premain(void* gprCtx, void* fpuCtx) { return QBDIPRELOAD_NOT_HANDLED; }

QBDI_EXPORT int qbdipreload_on_main(int argc, char** argv) { return QBDIPRELOAD_NOT_HANDLED; }

} // extern "C"