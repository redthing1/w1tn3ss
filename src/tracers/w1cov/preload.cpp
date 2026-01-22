#include <memory>
#include <string>
#include <utility>

#include "QBDIPreload.h"
#include <redlog.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1base/windows_console.hpp>
#endif

#include "w1instrument/self_exclude.hpp"
#include "w1instrument/process_tracer.hpp"
#include "w1runtime/process_monitor.hpp"

#include "coverage_config.hpp"
#include "coverage_engine.hpp"
#include "coverage_tracer.hpp"

namespace {

using block_tracer = w1cov::coverage_tracer<w1cov::coverage_mode::basic_block>;
using inst_tracer = w1cov::coverage_tracer<w1cov::coverage_mode::instruction>;
using block_process = w1::instrument::process_tracer<block_tracer>;
using inst_process = w1::instrument::process_tracer<inst_tracer>;

std::unique_ptr<block_process> g_block_process;
std::unique_ptr<inst_process> g_inst_process;
std::unique_ptr<w1::runtime::process_monitor> g_monitor;
std::shared_ptr<w1cov::coverage_engine> g_engine;
w1cov::coverage_config g_config;

void configure_logging(int verbose) {
  if (verbose >= 5) {
    redlog::set_level(redlog::level::annoying);
  } else if (verbose >= 4) {
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
}

template <typename ProcessT>
bool run_process(ProcessT& process, QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  auto* vm_ptr = static_cast<QBDI::VM*>(vm);
  return process.run_main(vm_ptr, static_cast<uint64_t>(start), static_cast<uint64_t>(stop), "main");
}

template <typename ProcessT>
typename ProcessT::config make_process_config(const w1cov::coverage_config& config) {
  typename ProcessT::config cfg{};
  cfg.instrumentation = config.instrumentation;
  cfg.attach_new_threads = true;
  cfg.refresh_on_module_events = true;
  cfg.owns_monitor = true;
  return cfg;
}

void shutdown_process() {
  if (g_block_process) {
    g_block_process->stop();
    g_block_process.reset();
  }
  if (g_inst_process) {
    g_inst_process->stop();
    g_inst_process.reset();
  }
}

} // namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  auto log = redlog::get_logger("w1cov.preload");

  g_config = w1cov::coverage_config::from_environment();
  configure_logging(g_config.verbose);
  if (g_config.exclude_self) {
    w1::util::append_self_excludes(g_config.instrumentation, reinterpret_cast<const void*>(&qbdipreload_on_run));
  }

  g_monitor = std::make_unique<w1::runtime::process_monitor>();
  g_monitor->modules().refresh();

  g_engine = std::make_shared<w1cov::coverage_engine>(g_config);
  g_engine->configure(g_monitor->modules());

  if (g_config.inst_trace) {
    auto process_config = make_process_config<inst_process>(g_config);
    g_inst_process = std::make_unique<inst_process>(
        *g_monitor, process_config,
        [engine = g_engine](const w1::runtime::thread_info&) { return inst_tracer(engine); }
    );
    g_inst_process->start();
    if (!run_process(*g_inst_process, vm, start, stop)) {
      log.err("coverage session run failed");
      return QBDIPRELOAD_ERR_STARTUP_FAILED;
    }
  } else {
    auto process_config = make_process_config<block_process>(g_config);
    g_block_process = std::make_unique<block_process>(
        *g_monitor, process_config,
        [engine = g_engine](const w1::runtime::thread_info&) { return block_tracer(engine); }
    );
    g_block_process->start();
    if (!run_process(*g_block_process, vm, start, stop)) {
      log.err("coverage session run failed");
      return QBDIPRELOAD_ERR_STARTUP_FAILED;
    }
  }

  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_exit(int status) {
  auto log = redlog::get_logger("w1cov.preload");
  log.inf("qbdipreload_on_exit called", redlog::field("status", status));

  shutdown_process();
  g_monitor.reset();

  if (g_engine) {
    if (!g_engine->export_coverage()) {
      log.wrn("coverage export produced no output", redlog::field("output_file", g_config.output_file));
    } else {
      log.inf("coverage data export completed", redlog::field("output_file", g_config.output_file));
    }
    log.inf(
        "coverage collection completed", redlog::field("coverage_units", g_engine->coverage_unit_count()),
        redlog::field("modules", g_engine->module_count()), redlog::field("total_hits", g_engine->total_hits())
    );
    g_engine.reset();
  }

  log.inf("qbdipreload_on_exit completed");
  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_start(void* main) {
  (void) main;
#if defined(_WIN32) || defined(WIN32)
  w1::common::allocate_windows_console();
#endif
  return QBDIPRELOAD_NOT_HANDLED;
}

QBDI_EXPORT int qbdipreload_on_premain(void* gpr_ctx, void* fpu_ctx) {
  (void) gpr_ctx;
  (void) fpu_ctx;
  return QBDIPRELOAD_NOT_HANDLED;
}

QBDI_EXPORT int qbdipreload_on_main(int argc, char** argv) {
  (void) argc;
  (void) argv;
  return QBDIPRELOAD_NOT_HANDLED;
}

} // extern "C"
