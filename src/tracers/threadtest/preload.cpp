#include <memory>
#include <vector>
#include <cstring>

#include "QBDIPreload.h"
#include <redlog.hpp>

#include <w1tn3ss/runtime/threading/thread_runtime.hpp>
#include <w1tn3ss/util/signal_handler.hpp>
#include <w1tn3ss/util/stderr_write.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1common/windows_console.hpp>
#endif

#include "threadtest_config.hpp"
#include "threadtest_session.hpp"

namespace {

auto log_preload() { return redlog::get_logger("threadtest.preload"); }

threadtest::threadtest_config g_config;
std::shared_ptr<threadtest::threadtest_session_factory> g_factory;
w1::runtime::threading::thread_context* g_main_context = nullptr;

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

} // namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  auto log = log_preload();
  log.inf("qbdipreload_on_run");

  g_config = threadtest::threadtest_config::from_environment();
  set_log_level(g_config.verbose);

  w1::runtime::threading::thread_runtime_options options;
  options.verbose = g_config.verbose;
  options.enable_thread_hooks = g_config.enable_thread_hooks;
  options.logger_prefix = "threadtest.thread";

  g_factory = std::make_shared<threadtest::threadtest_session_factory>(g_config);

  auto& service = w1::runtime::threading::thread_service::instance();
  service.configure(options, g_factory);

  w1::tn3ss::signal_handler::config sig_cfg;
  sig_cfg.context_name = "threadtest";
  sig_cfg.log_signals = g_config.verbose >= 2;

  if (w1::tn3ss::signal_handler::initialize(sig_cfg)) {
    w1::tn3ss::signal_handler::register_cleanup(shutdown_tracer, 100, "threadtest_shutdown");
  }

  g_main_context = service.register_main_thread(vm, "main");
  if (!g_main_context || !g_main_context->session) {
    log.err("failed to initialize main thread session");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  log.inf(
      "thread runtime ready", redlog::field("thread_id", g_main_context->thread_id),
      redlog::field("start", "0x%08x", start), redlog::field("stop", "0x%08x", stop)
  );

  auto* vm_ptr = static_cast<QBDI::VM*>(vm);
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
  auto& service = w1::runtime::threading::thread_service::instance();

  try {
    service.unregister_all();
  } catch (...) {
    const char* message = "threadtest: shutdown failure\n";
    w1::util::stderr_write(message);
  }

  g_main_context = nullptr;
  g_factory.reset();
}

} // namespace
