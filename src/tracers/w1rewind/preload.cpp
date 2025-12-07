#include <memory>
#include <vector>

#include "QBDIPreload.h"
#include <redlog.hpp>

#include <w1tn3ss/runtime/threading/thread_runtime.hpp>
#include <w1tn3ss/util/signal_handler.hpp>
#include <w1tn3ss/util/stderr_write.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1common/windows_console.hpp>
#endif

#include "rewind_config.hpp"
#include "rewind_session.hpp"

#include <w1tn3ss/runtime/rewind/binary_trace_sink.hpp>
#include <w1tn3ss/runtime/rewind/binary_trace_source.hpp>
#include <w1tn3ss/runtime/rewind/trace_validator.hpp>

namespace {

auto log_preload() { return redlog::get_logger("w1rewind.preload"); }

w1rewind::rewind_config g_config;
std::shared_ptr<w1rewind::rewind_session_factory> g_factory;
w1::runtime::threading::thread_context* g_main_context = nullptr;
w1::rewind::trace_sink_ptr g_sink;
w1::rewind::trace_source_ptr g_trace_source;
w1::rewind::trace_validator_ptr g_validator;

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

  g_config = w1rewind::rewind_config::from_environment();
  set_log_level(g_config.verbose);

  w1::rewind::binary_trace_sink_config sink_config;
  sink_config.path = g_config.output_path;
  sink_config.log = redlog::get_logger("w1rewind.trace");
  g_sink = w1::rewind::make_binary_trace_sink(std::move(sink_config));
  if (!g_sink || !g_sink->initialize()) {
    log.err("failed to initialize trace writer");
    g_sink.reset();
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  if (!g_config.compare_trace_path.empty()) {
    w1::rewind::binary_trace_source_config source_config;
    source_config.path = g_config.compare_trace_path;
    source_config.log = redlog::get_logger("w1rewind.trace_source");
    g_trace_source = w1::rewind::make_binary_trace_source(std::move(source_config));

    w1::rewind::validation_mode validator_mode = w1::rewind::validation_mode::strict;
    if (g_config.mode == w1rewind::rewind_config::validation_mode::log_only) {
      validator_mode = w1::rewind::validation_mode::log_only;
    }

    g_validator = std::make_shared<w1::rewind::trace_validator>(w1::rewind::trace_validator_config{
        .source = g_trace_source,
        .mode = validator_mode,
        .max_mismatches = g_config.max_mismatches,
        .stack_window_bytes = g_config.stack_window_bytes,
        .ignore_registers = g_config.ignore_registers,
        .ignore_modules = g_config.ignore_modules,
        .log = redlog::get_logger("w1rewind.validator"),
    });

    if (!g_validator->initialize()) {
      log.err("failed to initialize trace validator", redlog::field("trace", g_config.compare_trace_path));
      g_validator.reset();
      g_trace_source.reset();
      g_sink->close();
      g_sink.reset();
      return QBDIPRELOAD_ERR_STARTUP_FAILED;
    }
  }

  w1::runtime::threading::thread_runtime_options options;
  options.verbose = g_config.verbose;
  options.enable_thread_hooks = g_config.enable_thread_hooks;
  options.logger_prefix = "w1rewind.thread";

  g_factory = std::make_shared<w1rewind::rewind_session_factory>(g_config, g_sink, g_validator);

  auto& service = w1::runtime::threading::thread_service::instance();
  service.configure(options, g_factory);

  w1::tn3ss::signal_handler::config sig_cfg;
  sig_cfg.context_name = "w1rewind";
  sig_cfg.log_signals = g_config.verbose >= 2;

  if (w1::tn3ss::signal_handler::initialize(sig_cfg)) {
    w1::tn3ss::signal_handler::register_cleanup(shutdown_tracer, 100, "w1rewind_shutdown");
  }

  g_main_context = service.register_main_thread(vm, "main");
  if (!g_main_context || !g_main_context->session) {
    log.err("failed to initialize main thread session");
    shutdown_tracer();
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
  (void)main;
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
    const char* message = "w1rewind: shutdown failure\n";
    w1::util::stderr_write(message);
  }

  g_main_context = nullptr;
  g_factory.reset();
  if (g_sink) {
    g_sink->close();
    g_sink.reset();
  }
  if (g_validator) {
    g_validator->finalize();
    const auto& stats = g_validator->stats();
    log_preload().inf(
        "validation summary", redlog::field("checked", stats.events_checked),
        redlog::field("mismatches", stats.mismatches), redlog::field("aborted", stats.aborted)
    );
    g_validator->close();
    g_validator.reset();
  }
  if (g_trace_source) {
    g_trace_source->close();
    g_trace_source.reset();
  }
}

} // namespace
