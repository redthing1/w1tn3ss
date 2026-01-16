#include <memory>

#include "QBDIPreload.h"
#include <redlog.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1common/windows_console.hpp>
#endif

#include "rewind_config.hpp"
#include "rewind_tracer.hpp"

#include "w1tn3ss/runtime/rewind/trace_writer.hpp"
#include "w1tn3ss/tracer/trace_session.hpp"
#include "w1tn3ss/util/self_exclude.hpp"

namespace {

using rewind_session = w1::trace_session<w1rewind::rewind_tracer>;

std::unique_ptr<rewind_session> g_session;
w1rewind::rewind_config g_config;

void configure_logging(int verbose) {
  if (verbose >= 5) {
    redlog::set_level(redlog::level::annoying);
  } else if (verbose >= 4) {
    redlog::set_level(redlog::level::pedantic);
  } else if (verbose >= 3) {
    redlog::set_level(redlog::level::debug);
  } else if (verbose >= 2) {
    redlog::set_level(redlog::level::trace);
  } else if (verbose >= 1) {
    redlog::set_level(redlog::level::verbose);
  } else {
    redlog::set_level(redlog::level::info);
  }
}

void shutdown_tracer() {
  auto log = redlog::get_logger("w1rewind.preload");

  if (g_session) {
    g_session->shutdown(false);
  }
}

} // namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  auto log = redlog::get_logger("w1rewind.preload");
  log.inf("qbdipreload_on_run");

  g_config = w1rewind::rewind_config::from_environment();
  configure_logging(g_config.verbose);

  if (g_config.exclude_self) {
    w1::util::append_self_excludes(g_config.instrumentation, reinterpret_cast<const void*>(&qbdipreload_on_run));
  }

  w1::rewind::trace_writer_config writer_config;
  writer_config.path = g_config.output_path;
  writer_config.log = redlog::get_logger("w1rewind.trace");
  auto writer = w1::rewind::make_trace_writer(std::move(writer_config));
  if (!writer || !writer->open()) {
    log.err("failed to initialize trace writer");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  w1::trace_session_config session_config;
  session_config.instrumentation = g_config.instrumentation;
  session_config.thread_id = 1;
  session_config.thread_name = "main";

  g_session = std::make_unique<rewind_session>(session_config, vm, std::in_place, g_config, writer);

  log.inf(
      "starting rewind session", redlog::field("start", "0x%llx", static_cast<unsigned long long>(start)),
      redlog::field("stop", "0x%llx", static_cast<unsigned long long>(stop))
  );

  if (!g_session->run(static_cast<uint64_t>(start), static_cast<uint64_t>(stop))) {
    log.err("rewind session run failed");
    shutdown_tracer();
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_exit(int status) {
  auto log = redlog::get_logger("w1rewind.preload");
  log.inf("qbdipreload_on_exit", redlog::field("status", status));

  shutdown_tracer();
  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_start(void* main) {
  (void) main;
#if defined(_WIN32) || defined(WIN32)
  w1::common::allocate_windows_console();
#endif
  return QBDIPRELOAD_NOT_HANDLED;
}

QBDI_EXPORT int qbdipreload_on_premain(void*, void*) { return QBDIPRELOAD_NOT_HANDLED; }
QBDI_EXPORT int qbdipreload_on_main(int, char**) { return QBDIPRELOAD_NOT_HANDLED; }

} // extern "C"
