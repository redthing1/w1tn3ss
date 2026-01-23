#pragma once

#include <cstdint>

#include "QBDIPreload.h"
#include <QBDI.h>
#include <redlog.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1base/windows_console.hpp>
#endif

#include "config/coverage_config.hpp"
#include "runtime/coverage_runtime.hpp"
#include "w1instrument/logging.hpp"
#include "w1instrument/self_exclude.hpp"

namespace w1cov {

struct coverage_recipe {
  using config_t = coverage_config;
  using runtime_t = coverage_process_runtime_any;

  static config_t load_config() { return coverage_config::from_environment(); }

  static void configure_logging(const config_t& config) {
    w1::instrument::configure_redlog_verbosity(config.common.verbose, true);
  }

  static void apply_self_excludes(config_t& config, const void* anchor) {
    if (config.common.exclude_self) {
      w1::util::append_self_excludes(config.common.instrumentation, anchor);
    }
  }

  static void log_config(const config_t& config) {
    auto log = redlog::get_logger("w1cov.preload");
    const char* threads =
        config.threads == w1::instrument::config::thread_attach_policy::auto_attach ? "auto" : "main";
    log.inf(
        "qbdipreload_on_run configured", redlog::field("mode", coverage_mode_name(config.mode)),
        redlog::field("output_file", config.output_file),
        redlog::field("buffer_flush_threshold", config.buffer_flush_threshold), redlog::field("threads", threads)
    );
  }

  static runtime_t make_runtime(const config_t& config) { return make_process_runtime(config); }

  static bool run_main(runtime_t& runtime, QBDI::VM* vm, uint64_t start, uint64_t stop) {
    return with_runtime(runtime, [&](auto& active) { return active.run_main(vm, start, stop); });
  }

  static void on_exit(runtime_t& runtime, const config_t& config, int status) {
    auto log = redlog::get_logger("w1cov.preload");
    log.inf("qbdipreload_on_exit called", redlog::field("status", status));

    with_runtime(runtime, [&](auto& active) {
      active.stop();

      if (!active.export_output()) {
        log.wrn("coverage export produced no output", redlog::field("output_file", config.output_file));
      } else {
        log.inf("coverage data export completed", redlog::field("output_file", config.output_file));
      }

      auto& engine = active.engine();
      log.inf(
          "coverage collection completed", redlog::field("coverage_units", engine.coverage_unit_count()),
          redlog::field("modules", engine.module_count()), redlog::field("total_hits", engine.total_hits())
      );
    });

    log.inf("qbdipreload_on_exit completed");
  }

  static int on_start(void* main) {
    (void) main;
#if defined(_WIN32) || defined(WIN32)
    w1::common::allocate_windows_console();
#endif
    return QBDIPRELOAD_NOT_HANDLED;
  }

  static int on_premain(void* gpr_ctx, void* fpu_ctx) {
    (void) gpr_ctx;
    (void) fpu_ctx;
    return QBDIPRELOAD_NOT_HANDLED;
  }

  static int on_main(int argc, char** argv) {
    (void) argc;
    (void) argv;
    return QBDIPRELOAD_NOT_HANDLED;
  }
};

} // namespace w1cov
