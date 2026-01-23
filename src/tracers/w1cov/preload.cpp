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
#include "w1instrument/preload_driver.hpp"

#include "config/coverage_config.hpp"
#include "instrument/coverage_runtime.hpp"

namespace {

struct coverage_preload_policy {
  using config_type = w1cov::coverage_config;
  using runtime_type = w1cov::coverage_runtime;

  static config_type load_config() { return config_type::from_environment(); }

  static void configure_logging(const config_type& config) {
    w1::instrument::configure_redlog_verbosity(config.verbose, true);
  }

  static bool should_exclude_self(const config_type& config) { return config.exclude_self; }

  static void apply_self_excludes(config_type& config, const void* anchor) {
    w1::util::append_self_excludes(config.instrumentation, anchor);
  }

  static std::unique_ptr<runtime_type> create_runtime(const config_type& config, QBDI::VMInstanceRef) {
    return std::make_unique<runtime_type>(config);
  }

  static bool run(runtime_type& runtime, QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
    auto* vm_ptr = static_cast<QBDI::VM*>(vm);
    return runtime.run_main(vm_ptr, static_cast<uint64_t>(start), static_cast<uint64_t>(stop), "main");
  }

  static void shutdown(runtime_type& runtime, int status, const config_type& config) {
    auto log = redlog::get_logger("w1cov.preload");
    log.inf("qbdipreload_on_exit called", redlog::field("status", status));

    if (!runtime.export_coverage()) {
      log.wrn("coverage export produced no output", redlog::field("output_file", config.output_file));
    } else {
      log.inf("coverage data export completed", redlog::field("output_file", config.output_file));
    }

    auto& engine = runtime.engine();
    log.inf(
        "coverage collection completed", redlog::field("coverage_units", engine.coverage_unit_count()),
        redlog::field("modules", engine.module_count()), redlog::field("total_hits", engine.total_hits())
    );

    runtime.stop();
    log.inf("qbdipreload_on_exit completed");
  }
};

using preload_state = w1::instrument::preload_state<coverage_preload_policy>;

preload_state g_state;

} // namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  if (!w1::instrument::preload_run(g_state, reinterpret_cast<const void*>(&qbdipreload_on_run), vm, start, stop)) {
    auto log = redlog::get_logger("w1cov.preload");
    log.err("coverage session run failed");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_exit(int status) {
  w1::instrument::preload_shutdown(g_state, status);
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
