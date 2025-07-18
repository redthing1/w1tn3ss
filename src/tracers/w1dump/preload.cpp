#include <cstdlib>
#include <cstring>
#include <memory>

#include "QBDIPreload.h"
#include <redlog.hpp>

#include <w1tn3ss/engine/tracer_engine.hpp>
#include <w1tn3ss/util/env_config.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1common/windows_console.hpp>
#endif

#include "dump_config.hpp"
#include "dump_tracer.hpp"

// globals
static std::unique_ptr<w1dump::dump_tracer> g_tracer;
static std::unique_ptr<w1::tracer_engine<w1dump::dump_tracer>> g_engine;
static w1dump::dump_config g_config;

// parse size string like "10M", "1G", etc.
static uint64_t parse_size(const std::string& size_str) {
  uint64_t value = 0;
  char unit = 0;

  // parse number and optional unit
  size_t pos = 0;
  value = std::stoull(size_str, &pos);

  if (pos < size_str.length()) {
    unit = std::toupper(size_str[pos]);
  }

  // apply unit multiplier
  switch (unit) {
  case 'K':
    value *= 1024;
    break;
  case 'M':
    value *= 1024 * 1024;
    break;
  case 'G':
    value *= 1024 * 1024 * 1024;
    break;
  }

  return value;
}

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  auto log = redlog::get_logger("w1dump.preload");

  log.inf("qbdipreload_on_run called");

  // parse config from environment
  w1::util::env_config loader("W1DUMP_");

  // verbosity
  int verbose = loader.get<int>("VERBOSE", 0);
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

  // output file
  g_config.output = loader.get<std::string>("OUTPUT", "process.w1dump");

  // dump memory content
  g_config.dump_memory_content = loader.get<bool>("DUMP_MEMORY_CONTENT", false);

  // parse filters
  int filter_count = loader.get<int>("FILTER_COUNT", 0);
  for (int i = 0; i < filter_count; i++) {
    std::string key = "FILTER_" + std::to_string(i);
    std::string filter = loader.get<std::string>(key, "");
    if (!filter.empty()) {
      g_config.filters.push_back(filter);
    }
  }

  // parse max region size
  std::string max_size_str = loader.get<std::string>("MAX_REGION_SIZE", "");
  if (!max_size_str.empty()) {
    g_config.max_region_size = parse_size(max_size_str);
  }

  // dump on entry
  g_config.dump_on_entry = loader.get<bool>("DUMP_ON_ENTRY", true);

  // create tracer
  log.inf("creating tracer");
  g_tracer = std::make_unique<w1dump::dump_tracer>(g_config);

  // create engine with instrumentation config
  w1::instrumentation_config inst_config;
  inst_config.include_system_modules = g_config.include_system_modules;

  g_engine = std::make_unique<w1::tracer_engine<w1dump::dump_tracer>>(vm, *g_tracer, inst_config);

  // no tracer initialization needed for dump

  // instrument
  log.inf("instrumenting engine");
  if (!g_engine->instrument()) {
    log.err("engine instrumentation failed");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  log.inf("engine instrumentation successful");

  // trigger dump before running if configured
  if (g_config.dump_on_entry) {
    log.inf("performing initial dump");
    g_tracer->on_vm_start(vm);
  }

  // tell the process to kys (it's so over)

  return QBDIPRELOAD_ERR_STARTUP_FAILED; // we don't actually run the VM, just dump
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