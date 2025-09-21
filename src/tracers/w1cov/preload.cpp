#include <memory>
#include <vector>

#include "QBDIPreload.h"
#include <redlog.hpp>

#include <w1tn3ss/runtime/threading/thread_runtime.hpp>
#include <w1tn3ss/formats/drcov.hpp>
#include <w1tn3ss/util/env_config.hpp>
#include <w1tn3ss/util/signal_handler.hpp>
#include <w1tn3ss/util/stderr_write.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1common/windows_console.hpp>
#endif

#include "coverage_config.hpp"
#include "coverage_runtime.hpp"
#include "coverage_thread_session.hpp"

namespace {

auto log_preload() { return redlog::get_logger("w1cov.preload"); }

w1cov::coverage_config g_config;
std::shared_ptr<w1cov::coverage_thread_session_factory> g_factory;
w1::runtime::threading::thread_context* g_main_context = nullptr;
bool g_exported = false;

void shutdown_tracer();

void set_log_level(int verbose) {
  using level = redlog::level;
  if (verbose >= 5) {
    redlog::set_level(level::annoying);
  } else if (verbose >= 4) {
    redlog::set_level(level::pedantic);
  } else if (verbose >= 3) {
    redlog::set_level(level::debug);
  } else if (verbose >= 2) {
    redlog::set_level(level::trace);
  } else if (verbose >= 1) {
    redlog::set_level(level::verbose);
  } else {
    redlog::set_level(level::info);
  }
}

void export_coverage() {
  auto log = log_preload();

  if (g_exported) {
    log.vrb("coverage already exported; skipping");
    return;
  }

  try {
    auto& service = w1::runtime::threading::thread_service::instance();
    service.unregister_all();

    auto& runtime = w1cov::coverage_runtime::instance();
    auto data = runtime.build_drcov_data();
    if (!data.basic_blocks.empty()) {
      drcov::write(g_config.output_file, data);
      log.inf(
          "coverage export complete", redlog::field("file", g_config.output_file),
          redlog::field("basic_blocks", data.basic_blocks.size())
      );
      g_exported = true;
    } else {
      log.wrn("no coverage data collected; skipping export");
      g_exported = true;
    }
  } catch (const std::exception& e) {
    log.err("coverage export failed", redlog::field("error", e.what()));
    const char* message = "w1cov: coverage export failed\n";
    w1::util::stderr_write(message);
  }
}

} // namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  auto log = log_preload();
  log.inf("qbdipreload_on_run");

  g_config = w1cov::coverage_config::from_environment();
  set_log_level(g_config.verbose);

  auto& runtime = w1cov::coverage_runtime::instance();
  runtime.configure(g_config);

  w1::runtime::threading::thread_runtime_options thread_options;
  thread_options.verbose = g_config.verbose;
  thread_options.enable_thread_hooks = g_config.enable_thread_hooks;
  thread_options.logger_prefix = "w1cov.thread";

  g_factory = std::make_shared<w1cov::coverage_thread_session_factory>(runtime, g_config);

  auto& service = w1::runtime::threading::thread_service::instance();
  service.configure(thread_options, g_factory);

  w1::tn3ss::signal_handler::config sig_cfg;
  sig_cfg.context_name = "w1cov";
  sig_cfg.log_signals = (g_config.verbose >= 1);

  if (w1::tn3ss::signal_handler::initialize(sig_cfg)) {
    w1::tn3ss::signal_handler::register_cleanup(export_coverage, 200, "w1cov_export");
    log.inf("signal handlers armed for coverage export");
  } else {
    log.wrn("failed to initialize signal handling");
  }

  g_main_context = service.register_main_thread(vm, "main");
  if (!g_main_context || !g_main_context->session) {
    log.err("failed to initialize main thread session");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  auto* vm_ptr = static_cast<QBDI::VM*>(vm);
  log.inf(
      "starting instrumented execution", redlog::field("start", "0x%08x", start), redlog::field("stop", "0x%08x", stop)
  );

  if (!vm_ptr->run(start, stop)) {
    log.err("vm run failed");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_exit(int status) {
  auto log = log_preload();
  log.inf("qbdipreload_on_exit", redlog::field("status", status));

  shutdown_tracer();
  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_start(void* main) {
#if defined(_WIN32) || defined(WIN32)
  w1::common::allocate_windows_console();
#endif
  return QBDIPRELOAD_NOT_HANDLED;
}

QBDI_EXPORT int qbdipreload_on_premain(void*, void*) { return QBDIPRELOAD_NOT_HANDLED; }
QBDI_EXPORT int qbdipreload_on_main(int, char**) { return QBDIPRELOAD_NOT_HANDLED; }

} // extern "C"

namespace {

void shutdown_tracer() {
  auto log = log_preload();

  try {
    export_coverage();
  } catch (...) {
    const char* message = "w1cov: shutdown failure\n";
    w1::util::stderr_write(message);
  }

  g_main_context = nullptr;
  g_factory.reset();

  auto& runtime = w1cov::coverage_runtime::instance();
  runtime.reset();

  log.inf("w1cov shutdown complete");
}

} // namespace
