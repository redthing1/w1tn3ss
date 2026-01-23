#include <memory>
#include <utility>

#include "QBDIPreload.h"
#include <redlog.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1base/windows_console.hpp>
#endif

#include "w1instrument/tracer/vm_session.hpp"
#include "w1instrument/self_exclude.hpp"
#include "w1instrument/logging.hpp"
#include "w1instrument/preload_driver.hpp"

#include "config/dump_config.hpp"
#include "engine/dump_engine.hpp"
#include "instrument/dump_recorder.hpp"

namespace {

struct dump_runtime {
  std::shared_ptr<w1dump::dump_engine> engine;
  std::unique_ptr<w1::vm_session<w1dump::dump_recorder>> session;
};

struct dump_preload_policy {
  using config_type = w1dump::dump_config;
  using runtime_type = dump_runtime;

  static config_type load_config() { return config_type::from_environment(); }

  static void configure_logging(const config_type& config) {
    w1::instrument::configure_redlog_verbosity(config.verbose);
  }

  static bool should_exclude_self(const config_type& config) { return config.exclude_self; }

  static void apply_self_excludes(config_type& config, const void* anchor) {
    w1::util::append_self_excludes(config.instrumentation, anchor);
  }

  static std::unique_ptr<runtime_type> create_runtime(const config_type& config, QBDI::VMInstanceRef vm) {
    auto runtime = std::make_unique<runtime_type>();

    w1::vm_session_config session_config;
    session_config.instrumentation = config.instrumentation;
    session_config.thread_id = 1;
    session_config.thread_name = "main";

    runtime->engine = std::make_shared<w1dump::dump_engine>(config);
    auto* vm_ptr = static_cast<QBDI::VM*>(vm);
    runtime->session = std::make_unique<w1::vm_session<w1dump::dump_recorder>>(
        session_config, vm_ptr, std::in_place, runtime->engine
    );

    return runtime;
  }

  static bool run(runtime_type& runtime, QBDI::VMInstanceRef, QBDI::rword start, QBDI::rword stop) {
    auto log = redlog::get_logger("w1dump.preload");
    log.inf(
        "starting dump session", redlog::field("start", "0x%llx", static_cast<unsigned long long>(start)),
        redlog::field("stop", "0x%llx", static_cast<unsigned long long>(stop))
    );

    if (!runtime.session) {
      return false;
    }

    bool run_ok = runtime.session->run(static_cast<uint64_t>(start), static_cast<uint64_t>(stop));
    if (!run_ok) {
      if (runtime.session->tracer().dump_completed()) {
        log.inf("dump session stopped after snapshot");
      } else {
        log.wrn("dump session ended early");
      }
    }

    return true;
  }

  static void shutdown(runtime_type& runtime, int status, const config_type&) {
    auto log = redlog::get_logger("w1dump.preload");
    log.inf("qbdipreload_on_exit called", redlog::field("status", status));

    if (runtime.session) {
      runtime.session->shutdown(false);
    }

    log.inf("qbdipreload_on_exit completed");
  }
};

using preload_state = w1::instrument::preload_state<dump_preload_policy>;

preload_state g_state;

} // namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  if (!w1::instrument::preload_run(g_state, reinterpret_cast<const void*>(&qbdipreload_on_run), vm, start, stop)) {
    auto log = redlog::get_logger("w1dump.preload");
    log.err("dump session run failed");
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
