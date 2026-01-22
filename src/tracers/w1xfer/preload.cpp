#include <memory>
#include <utility>

#include "QBDIPreload.h"
#include <redlog.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1base/windows_console.hpp>
#endif

#include "w1instrument/self_exclude.hpp"
#include "w1instrument/preload_driver.hpp"
#include "w1instrument/tracer/vm_session.hpp"
#include "w1instrument/logging.hpp"

#include "transfer_config.hpp"
#include "transfer_recorder.hpp"

namespace {

struct transfer_preload_policy {
  using config_type = w1xfer::transfer_config;
  using runtime_type = w1::vm_session<w1xfer::transfer_recorder>;

  static config_type load_config() { return config_type::from_environment(); }

  static void configure_logging(const config_type& config) {
    w1::instrument::configure_redlog_verbosity(config.verbose);
  }

  static bool should_exclude_self(const config_type& config) { return config.exclude_self; }

  static void apply_self_excludes(config_type& config, const void* anchor) {
    w1::util::append_self_excludes(config.instrumentation, anchor);
  }

  static std::unique_ptr<runtime_type> create_runtime(const config_type& config, QBDI::VMInstanceRef vm) {
    w1::vm_session_config session_config;
    session_config.instrumentation = config.instrumentation;
    session_config.thread_id = 1;
    session_config.thread_name = "main";

    auto* vm_ptr = static_cast<QBDI::VM*>(vm);
    return std::make_unique<runtime_type>(session_config, vm_ptr, std::in_place, config);
  }

  static bool run(runtime_type& session, QBDI::VMInstanceRef, QBDI::rword start, QBDI::rword stop) {
    auto log = redlog::get_logger("w1xfer.preload");
    log.inf(
        "starting transfer session", redlog::field("start", "0x%016llx", start), redlog::field("stop", "0x%016llx", stop)
    );
    return session.run(static_cast<uint64_t>(start), static_cast<uint64_t>(stop));
  }

  static void shutdown(runtime_type& session, int status, const config_type&) {
    auto log = redlog::get_logger("w1xfer.preload");
    log.inf("qbdipreload_on_exit called", redlog::field("status", status));
    session.shutdown(false);
    log.inf("qbdipreload_on_exit completed");
  }
};

using preload_state = w1::instrument::preload_state<transfer_preload_policy>;

preload_state g_state;

} // namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  if (!w1::instrument::preload_run(g_state, reinterpret_cast<const void*>(&qbdipreload_on_run), vm, start, stop)) {
    auto log = redlog::get_logger("w1xfer.preload");
    log.err("transfer session run failed");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_exit(int status) {
  w1::instrument::preload_shutdown(g_state, status);
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
