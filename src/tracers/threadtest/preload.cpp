#include <memory>
#include <vector>
#include <cstring>

#include "QBDIPreload.h"
#include <redlog.hpp>

#include <w1tn3ss/engine/tracer_engine.hpp>
#include <w1tn3ss/util/signal_handler.hpp>
#include <w1tn3ss/util/stderr_write.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1common/windows_console.hpp>
#endif

#include "thread_manager.hpp"
#include "threadtest_config.hpp"
#include "threadtest_tracer.hpp"
#include "thread_hook.hpp"

namespace {

auto log_preload() { return redlog::get_logger("threadtest.preload"); }

auto log_hook() { return redlog::get_logger("threadtest.interpose"); }

threadtest::thread_context* g_main_context = nullptr;
threadtest::thread_manager& g_manager = threadtest::thread_manager::instance();
threadtest::threadtest_config g_config;

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

threadtest::thread_result_t intercept_thread_start(threadtest::thread_start_fn start_routine, void* arg) {
  auto& manager = threadtest::thread_manager::instance();

  if (!manager.is_configured() || !start_routine) {
    log_hook().dbg("thread interception unavailable; executing start routine directly");
    return start_routine ? start_routine(arg) : threadtest::thread_result_t{};
  }

  threadtest::thread_context* context = manager.attach_thread(0, "worker");
  if (!context) {
    log_hook().wrn("failed to attach thread context; executing start routine directly");
    return start_routine(arg);
  }

  context->log.dbg("thread attached", redlog::field("thread_id", context->thread_id));

  bool instrumentation_ready = false;
  if (context->tracer && context->engine) {
    instrumentation_ready = context->tracer->initialize(*context->engine);
    if (instrumentation_ready) {
      instrumentation_ready = context->engine->instrument();
    }
  }

  threadtest::thread_result_t result{};

  if (instrumentation_ready && context->engine) {
    QBDI::rword retval = 0;
    std::vector<QBDI::rword> args = {reinterpret_cast<QBDI::rword>(arg)};
    if (context->engine->call_with_stack(&retval, reinterpret_cast<QBDI::rword>(start_routine), args)) {
#if defined(_WIN32)
      result = static_cast<threadtest::thread_result_t>(retval);
#else
      result = reinterpret_cast<threadtest::thread_result_t>(retval);
#endif
    } else {
      context->log.wrn("call_with_stack failed; executing start routine directly");
      result = start_routine(arg);
    }
  } else {
    context->log.dbg("instrumentation unavailable; executing start routine directly");
    result = start_routine(arg);
  }

  if (context->tracer) {
    context->tracer->shutdown();
  }

  manager.detach_thread(0);
  return result;
}

} // namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  auto log = log_preload();
  log.inf("qbdipreload_on_run");

  g_config = threadtest::threadtest_config::from_environment();
  set_log_level(g_config.verbose);
  g_manager.configure(g_config);

  if (g_config.enable_thread_hooks) {
    if (!threadtest::hooking::install(intercept_thread_start)) {
      log.wrn("failed to install thread hooks; worker threads will not be instrumented");
    }
  } else {
    log.wrn("thread hooks disabled via configuration");
  }

  w1::tn3ss::signal_handler::config sig_cfg;
  sig_cfg.context_name = "threadtest";
  sig_cfg.log_signals = g_config.verbose >= 2;

  if (w1::tn3ss::signal_handler::initialize(sig_cfg)) {
    w1::tn3ss::signal_handler::register_cleanup(shutdown_tracer, 100, "threadtest_shutdown");
  }

  g_main_context = g_manager.register_main_thread(vm);
  if (!g_main_context || !g_main_context->tracer || !g_main_context->engine) {
    log.err("failed to create main thread context");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  if (!g_main_context->tracer->initialize(*g_main_context->engine)) {
    log.err("main tracer initialization failed");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  if (!g_main_context->engine->instrument()) {
    log.err("main engine instrumentation failed");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  log.inf(
      "engine instrumented", redlog::field("thread_id", g_main_context->thread_id),
      redlog::field("start", "0x%08x", start), redlog::field("stop", "0x%08x", stop)
  );

  if (!g_main_context->engine->run(start, stop)) {
    log.err("engine run failed");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_exit(int status) {
  auto log = log_preload();
  log.inf("qbdipreload_on_exit", redlog::field("status", status));

  shutdown_tracer();
  threadtest::hooking::uninstall();
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
  if (!g_main_context || !g_main_context->tracer) {
    return;
  }

  try {
    g_main_context->tracer->shutdown();
  } catch (...) {
    const char* message = "threadtest: shutdown failure\n";
    w1::util::stderr_write(message);
  }

  g_main_context = nullptr;
}

} // namespace
