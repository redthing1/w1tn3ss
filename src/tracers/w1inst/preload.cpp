#include "QBDIPreload.h"
#include <redlog.hpp>

#if defined(_WIN32) || defined(WIN32)
#include <w1base/windows_console.hpp>
#endif

#include "w1instrument/preload_vm_session.hpp"

#include "instruction_config.hpp"
#include "instruction_tracer.hpp"

namespace {

struct instruction_preload_policy
    : w1::instrument::
          vm_session_preload_policy<instruction_preload_policy, w1inst::instruction_config, w1inst::instruction_tracer> {
  static constexpr const char* kLoggerName = "w1inst.preload";
  static constexpr const char* kSessionLabel = "instruction";
  static constexpr const char* kRunFailedMessage = "instruction session run failed";
};

using preload_state = w1::instrument::preload_state<instruction_preload_policy>;

preload_state g_state;

} // namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  try {
    if (!w1::instrument::preload_run_or_log(g_state, reinterpret_cast<const void*>(&qbdipreload_on_run), vm, start,
                                            stop)) {
      return QBDIPRELOAD_ERR_STARTUP_FAILED;
    }
  } catch (const std::exception& error) {
    auto log = redlog::get_logger(instruction_preload_policy::logger_name());
    log.err("failed to load instruction config", redlog::field("error", error.what()));
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
