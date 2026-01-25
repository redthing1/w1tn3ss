#include "QBDIPreload.h"

#include "script_recipe.hpp"
#include "w1instrument/preload/entrypoints.hpp"

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  return w1::instrument::preload_on_run<w1::tracers::script::script_recipe>(vm, start, stop);
}

QBDI_EXPORT int qbdipreload_on_exit(int status) {
  return w1::instrument::preload_on_exit<w1::tracers::script::script_recipe>(status);
}

QBDI_EXPORT int qbdipreload_on_start(void* main) {
  return w1::instrument::preload_on_start<w1::tracers::script::script_recipe>(main);
}

QBDI_EXPORT int qbdipreload_on_premain(void* gpr_ctx, void* fpu_ctx) {
  return w1::instrument::preload_on_premain<w1::tracers::script::script_recipe>(gpr_ctx, fpu_ctx);
}

QBDI_EXPORT int qbdipreload_on_main(int argc, char** argv) {
  return w1::instrument::preload_on_main<w1::tracers::script::script_recipe>(argc, argv);
}

} // extern "C"
