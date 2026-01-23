#pragma once

#include <cstdint>

#include "QBDIPreload.h"
#include <QBDI.h>
#include <redlog.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1base/windows_console.hpp>
#endif

#include "config/script_config.hpp"
#include "runtime/script_runtime.hpp"
#include "w1instrument/logging.hpp"
#include "w1instrument/self_exclude.hpp"

namespace w1::tracers::script {

struct script_recipe {
  using config_t = script_config;
  using runtime_t = script_runtime;

  static config_t load_config() { return script_config::from_environment(); }

  static void configure_logging(const config_t& config) {
    w1::instrument::configure_redlog_verbosity(config.verbose);
  }

  static void apply_self_excludes(config_t& config, const void* anchor) {
    if (config.exclude_self) {
      w1::util::append_self_excludes(config.instrumentation, anchor);
    }
  }

  static void log_config(const config_t& config) {
    auto log = redlog::get_logger("w1script.preload");
    log.inf(
        "qbdipreload_on_run configured", redlog::field("script", config.script_path),
        redlog::field("script_args", static_cast<uint64_t>(config.script_args.size()))
    );
  }

  static runtime_t make_runtime(const config_t& config) { return make_script_runtime(config); }

  static bool run_main(runtime_t& runtime, QBDI::VM* vm, uint64_t start, uint64_t stop) {
    if (!runtime.session) {
      return false;
    }

    auto log = redlog::get_logger("w1script.preload");
    log.inf(
        "starting script session", redlog::field("start", "0x%llx", static_cast<unsigned long long>(start)),
        redlog::field("stop", "0x%llx", static_cast<unsigned long long>(stop))
    );

    return runtime.session->run(vm, start, stop, "main");
  }

  static void on_exit(runtime_t& runtime, const config_t& config, int status) {
    auto log = redlog::get_logger("w1script.preload");
    log.inf("qbdipreload_on_exit called", redlog::field("status", status));

    if (runtime.session) {
      runtime.session->export_output();
    }

    if (!config.script_path.empty()) {
      log.inf("script session completed", redlog::field("script", config.script_path));
    }

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

} // namespace w1::tracers::script
