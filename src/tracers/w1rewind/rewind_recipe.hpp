#pragma once

#include <string>

#include "QBDIPreload.h"
#include <QBDI.h>
#include <redlog.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1base/windows_console.hpp>
#endif

#include "config/rewind_config.hpp"
#include "runtime/rewind_runtime.hpp"
#include "w1instrument/logging.hpp"
#include "w1instrument/self_exclude.hpp"

namespace w1rewind {
namespace {

using flow_mode = rewind_config::flow_options::flow_mode;

const char* flow_name(flow_mode mode) {
  switch (mode) {
  case rewind_config::flow_options::flow_mode::instruction:
    return "instruction";
  case rewind_config::flow_options::flow_mode::block:
  default:
    return "block";
  }
}

const char* memory_access_name(rewind_config::memory_access access) {
  switch (access) {
  case rewind_config::memory_access::reads:
    return "reads";
  case rewind_config::memory_access::writes:
    return "writes";
  case rewind_config::memory_access::reads_writes:
    return "reads_writes";
  case rewind_config::memory_access::none:
  default:
    return "none";
  }
}

bool has_filter(const std::vector<rewind_config::memory_filter_kind>& filters, rewind_config::memory_filter_kind kind) {
  for (const auto& entry : filters) {
    if (entry == kind) {
      return true;
    }
  }
  return false;
}

} // namespace

struct rewind_recipe {
  using config_t = rewind_config;
  using runtime_t = rewind_process_runtime_any;

  static config_t load_config() {
    std::string error;
    auto config = config_t::from_environment(error);
    if (!error.empty()) {
      auto log = redlog::get_logger("w1rewind.preload");
      log.err("invalid rewind config", redlog::field("error", error));
    }
    return config;
  }

  static void configure_logging(const config_t& config) {
    w1::instrument::configure_redlog_verbosity(config.common.verbose, true);
  }

  static void apply_self_excludes(config_t& config, const void* anchor) {
    if (config.common.exclude_self) {
      w1::util::append_self_excludes(config.common.instrumentation, anchor);
    }
  }

  static void log_config(const config_t& config) {
    auto log = redlog::get_logger("w1rewind.preload");
    const char* threads = config.threads == w1::instrument::config::thread_attach_policy::auto_attach ? "auto" : "main";
    log.inf(
        "qbdipreload_on_run configured", redlog::field("flow", flow_name(config.flow.mode)),
        redlog::field("output", config.output_path.empty() ? "default" : config.output_path),
        redlog::field("threads", threads), redlog::field("memory", memory_access_name(config.memory.access)),
        redlog::field("reg_deltas", config.registers.deltas),
        redlog::field("snapshots", config.registers.snapshot_interval),
        redlog::field("stack_snapshots", config.stack_snapshots.interval)
    );

    if (config.memory.access != rewind_config::memory_access::none && !config.memory.values) {
      log.wrn("memory values disabled; replayable memory state will be incomplete");
    }
    if (!config.memory.ranges.empty() &&
        !has_filter(config.memory.filters, rewind_config::memory_filter_kind::ranges)) {
      log.wrn("memory ranges configured but ranges filter not enabled");
    }
  }

  static runtime_t make_runtime(const config_t& config) { return make_process_runtime(config); }

  static bool run_main(runtime_t& runtime, QBDI::VM* vm, uint64_t start, uint64_t stop) {
    return with_runtime(runtime, [&](auto& active) { return active.run_main(vm, start, stop); });
  }

  static void on_exit(runtime_t& runtime, const config_t& config, int status) {
    auto log = redlog::get_logger("w1rewind.preload");
    log.inf("qbdipreload_on_exit called", redlog::field("status", status));

    with_runtime(runtime, [&](auto& active) {
      active.stop();
      if (!active.export_output()) {
        log.err("trace export failed", redlog::field("output", config.output_path));
      } else {
        const std::string output = config.output_path.empty() ? active.engine().output_path() : config.output_path;
        log.inf("trace export completed", redlog::field("output", output));
      }
      auto& engine = active.engine();
      log.inf("trace summary", redlog::field("images", engine.image_count()));
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

} // namespace w1rewind
