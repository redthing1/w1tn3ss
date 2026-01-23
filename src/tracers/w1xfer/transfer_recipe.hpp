#pragma once

#include <cstdint>

#include "QBDIPreload.h"
#include <QBDI.h>
#include <redlog.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1base/windows_console.hpp>
#endif

#include "config/transfer_config.hpp"
#include "runtime/transfer_runtime.hpp"
#include "w1instrument/logging.hpp"
#include "w1instrument/self_exclude.hpp"

namespace w1xfer {

struct transfer_recipe {
  using config_t = transfer_config;
  using runtime_t = transfer_runtime;

  static config_t load_config() { return transfer_config::from_environment(); }

  static void configure_logging(const config_t& config) {
    w1::instrument::configure_redlog_verbosity(config.verbose);
  }

  static void apply_self_excludes(config_t& config, const void* anchor) {
    if (config.exclude_self) {
      w1::util::append_self_excludes(config.instrumentation, anchor);
    }
  }

  static void log_config(const config_t& config) {
    auto log = redlog::get_logger("w1xfer.preload");
    log.inf(
        "qbdipreload_on_run configured", redlog::field("output", config.output.path),
        redlog::field("capture_registers", config.capture.registers),
        redlog::field("capture_stack", config.capture.stack), redlog::field("enrich_modules", config.enrich.modules),
        redlog::field("enrich_symbols", config.enrich.symbols),
        redlog::field("analyze_apis", config.enrich.analyze_apis),
        redlog::field("api_arg_count", static_cast<uint64_t>(config.enrich.api_argument_count))
    );
  }

  static runtime_t make_runtime(const config_t& config) { return make_transfer_runtime(config); }

  static bool run_main(runtime_t& runtime, QBDI::VM* vm, uint64_t start, uint64_t stop) {
    auto log = redlog::get_logger("w1xfer.preload");
    log.inf(
        "starting transfer session", redlog::field("start", "0x%llx", static_cast<unsigned long long>(start)),
        redlog::field("stop", "0x%llx", static_cast<unsigned long long>(stop))
    );

    if (!runtime.session) {
      return false;
    }

    return runtime.session->run(vm, start, stop, "main");
  }

  static void on_exit(runtime_t& runtime, const config_t& config, int status) {
    auto log = redlog::get_logger("w1xfer.preload");
    log.inf("qbdipreload_on_exit called", redlog::field("status", status));

    if (!runtime.session) {
      log.inf("qbdipreload_on_exit completed");
      return;
    }

    const bool exported = runtime.session->export_output();
    const auto& stats = runtime.session->engine().stats();

    if (!exported && !config.output.path.empty()) {
      log.wrn("transfer export produced no output", redlog::field("output", config.output.path));
    } else if (exported) {
      log.inf("transfer export completed", redlog::field("output", config.output.path));
    }

    log.inf(
        "transfer collection completed", redlog::field("total_calls", stats.total_calls),
        redlog::field("total_returns", stats.total_returns),
        redlog::field("unique_targets", stats.unique_call_targets),
        redlog::field("max_depth", stats.max_call_depth)
    );

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

} // namespace w1xfer
