#include <memory>
#include <utility>

#include "QBDIPreload.h"
#include <redlog.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1base/windows_console.hpp>
#endif

#include "w1instrument/tracer/vm_session.hpp"
#include "w1instrument/self_exclude.hpp"

#include "instruction_config.hpp"
#include "instruction_tracer.hpp"

static std::unique_ptr<w1::vm_session<w1inst::instruction_tracer>> g_session;
static w1inst::instruction_config g_config;

namespace {

void configure_logging(int verbose) {
  if (verbose >= 4) {
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

} // namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  auto log = redlog::get_logger("w1inst.preload");

  try {
    g_config = w1inst::instruction_config::from_environment();
  } catch (const std::exception& error) {
    log.err("failed to load instruction config", redlog::field("error", error.what()));
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  configure_logging(g_config.verbose);
  if (g_config.exclude_self) {
    w1::util::append_self_excludes(g_config.instrumentation, reinterpret_cast<const void*>(&qbdipreload_on_run));
  }

  w1::vm_session_config session_config;
  session_config.instrumentation = g_config.instrumentation;
  session_config.thread_id = 1;
  session_config.thread_name = "main";

  g_session =
      std::make_unique<w1::vm_session<w1inst::instruction_tracer>>(session_config, vm, std::in_place, g_config);

  log.inf(
      "starting instruction session", redlog::field("start", "0x%llx", static_cast<unsigned long long>(start)),
      redlog::field("stop", "0x%llx", static_cast<unsigned long long>(stop))
  );

  if (!g_session->run(static_cast<uint64_t>(start), static_cast<uint64_t>(stop))) {
    log.err("instruction session run failed");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_exit(int status) {
  auto log = redlog::get_logger("w1inst.preload");
  log.inf("qbdipreload_on_exit called", redlog::field("status", status));

  if (g_session) {
    g_session->shutdown(false);
    g_session.reset();
  }

  log.inf("qbdipreload_on_exit completed");
  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_start(void* main) {
  (void) main;
#if defined(_WIN32) || defined(WIN32)
  w1::common::allocate_windows_console();
#endif
  return QBDIPRELOAD_NOT_HANDLED;
}

QBDI_EXPORT int qbdipreload_on_premain(void* gpr_ctx, void* fpu_ctx) {
  (void) gpr_ctx;
  (void) fpu_ctx;
  return QBDIPRELOAD_NOT_HANDLED;
}

QBDI_EXPORT int qbdipreload_on_main(int argc, char** argv) {
  (void) argc;
  (void) argv;
  return QBDIPRELOAD_NOT_HANDLED;
}

} // extern "C"
