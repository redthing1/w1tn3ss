#include <memory>
#include <string>
#include <utility>

#include "QBDIPreload.h"
#include <redlog.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1base/windows_console.hpp>
#endif

#include "w1instrument/self_exclude.hpp"
#include "w1instrument/logging.hpp"

#include "config/coverage_config.hpp"
#include "instrument/coverage_runtime.hpp"

namespace {

std::unique_ptr<w1cov::coverage_runtime> g_runtime;
w1cov::coverage_config g_config;

void shutdown_runtime() {
  if (g_runtime) {
    g_runtime->stop();
    g_runtime.reset();
  }
}

} // namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  auto log = redlog::get_logger("w1cov.preload");

  g_config = w1cov::coverage_config::from_environment();
  w1::instrument::configure_redlog_verbosity(g_config.verbose, true);
  if (g_config.exclude_self) {
    w1::util::append_self_excludes(g_config.instrumentation, reinterpret_cast<const void*>(&qbdipreload_on_run));
  }

  g_runtime = std::make_unique<w1cov::coverage_runtime>(g_config);
  auto* vm_ptr = static_cast<QBDI::VM*>(vm);
  if (!g_runtime->run_main(vm_ptr, static_cast<uint64_t>(start), static_cast<uint64_t>(stop), "main")) {
    log.err("coverage session run failed");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_exit(int status) {
  auto log = redlog::get_logger("w1cov.preload");
  log.inf("qbdipreload_on_exit called", redlog::field("status", status));

  if (g_runtime) {
    if (!g_runtime->export_coverage()) {
      log.wrn("coverage export produced no output", redlog::field("output_file", g_config.output_file));
    } else {
      log.inf("coverage data export completed", redlog::field("output_file", g_config.output_file));
    }

    auto& engine = g_runtime->engine();
    log.inf(
        "coverage collection completed", redlog::field("coverage_units", engine.coverage_unit_count()),
        redlog::field("modules", engine.module_count()), redlog::field("total_hits", engine.total_hits())
    );
  }

  shutdown_runtime();

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
