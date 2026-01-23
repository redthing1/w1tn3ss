#include "QBDIPreload.h"

#if defined(_WIN32) || defined(WIN32)
#include <w1base/windows_console.hpp>
#endif

#include "w1instrument/preload_vm_session.hpp"

#include "script_config.hpp"
#include "script_tracer.hpp"

namespace {

struct script_preload_policy
    : w1::instrument::vm_session_preload_policy<script_preload_policy, w1::tracers::script::script_config,
                                                 w1::tracers::script::script_tracer> {
  static constexpr const char* kLoggerName = "w1script.preload";
  static constexpr const char* kSessionLabel = "script";
  static constexpr const char* kRunFailedMessage = "script session run failed";
};

using preload_state = w1::instrument::preload_state<script_preload_policy>;

preload_state g_state;

} // namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  if (!w1::instrument::preload_run_or_log(g_state, reinterpret_cast<const void*>(&qbdipreload_on_run), vm, start,
                                          stop)) {
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
