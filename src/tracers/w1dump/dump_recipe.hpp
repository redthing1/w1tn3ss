#pragma once

#include <cstdint>

#include "QBDIPreload.h"
#include <QBDI.h>
#include <redlog.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1base/windows_console.hpp>
#endif

#include "config/dump_config.hpp"
#include "runtime/dump_runtime.hpp"
#include "w1instrument/logging.hpp"
#include "w1instrument/self_exclude.hpp"

namespace w1dump {

struct dump_recipe {
  using config_t = dump_config;
  using runtime_t = dump_runtime;

  static config_t load_config() { return dump_config::from_environment(); }

  static void configure_logging(const config_t& config) {
    w1::instrument::configure_redlog_verbosity(config.common.verbose);
  }

  static void apply_self_excludes(config_t& config, const void* anchor) {
    if (config.common.exclude_self) {
      w1::util::append_self_excludes(config.common.instrumentation, anchor);
    }
  }

  static void log_config(const config_t& config) {
    auto log = redlog::get_logger("w1dump.preload");
    log.inf(
        "qbdipreload_on_run configured", redlog::field("output", config.output),
        redlog::field("trigger", dump_config::trigger_name(config.trigger)),
        redlog::field("dump_memory", config.dump_memory_content),
        redlog::field("filters", static_cast<uint64_t>(config.filters.size())),
        redlog::field("max_region_size", config.max_region_size)
    );
    if (config.trigger_address) {
      log.inf("dump trigger address", redlog::field("address", "0x%llx", config.trigger_address.value()));
    }
    if (!config.trigger_module.empty()) {
      log.inf("dump trigger module", redlog::field("module", config.trigger_module));
    }
    if (config.trigger_offset) {
      log.inf("dump trigger offset", redlog::field("offset", "0x%llx", config.trigger_offset.value()));
    }
  }

  static runtime_t make_runtime(const config_t& config) { return make_dump_runtime(config); }

  static bool run_main(runtime_t& runtime, QBDI::VM* vm, uint64_t start, uint64_t stop) {
    auto log = redlog::get_logger("w1dump.preload");
    log.inf(
        "starting dump session", redlog::field("start", "0x%llx", static_cast<unsigned long long>(start)),
        redlog::field("stop", "0x%llx", static_cast<unsigned long long>(stop))
    );

    if (!runtime.session) {
      return false;
    }

    const bool run_ok = runtime.session->run(vm, start, stop, "main");
    const bool dump_ok = runtime.session->engine().dump_completed();
    if (!run_ok) {
      if (dump_ok) {
        log.inf("dump session stopped after snapshot");
      } else {
        log.wrn("dump session ended early");
      }
    }

    return run_ok || dump_ok;
  }

  static void on_exit(runtime_t& runtime, const config_t& config, int status) {
    auto log = redlog::get_logger("w1dump.preload");
    log.inf("qbdipreload_on_exit called", redlog::field("status", status));

    if (runtime.session) {
      runtime.session->stop();
      if (runtime.session->engine().dump_completed()) {
        log.inf("dump completed", redlog::field("output", config.output));
      } else {
        log.wrn("dump not completed", redlog::field("output", config.output));
      }
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

} // namespace w1dump
