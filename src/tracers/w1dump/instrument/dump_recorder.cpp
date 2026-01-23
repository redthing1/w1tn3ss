#include "dump_recorder.hpp"

namespace w1dump {

dump_recorder::dump_recorder(std::shared_ptr<dump_engine> engine) : engine_(std::move(engine)) {}

QBDI::VMAction dump_recorder::on_vm_start(
    w1::trace_context& ctx, const w1::sequence_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  (void) event;
  (void) state;

  if (engine_ && engine_->config().dump_on_entry && !engine_->dump_completed()) {
    engine_->dump_once(ctx, vm, gpr, fpr);
    return QBDI::VMAction::STOP;
  }

  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction dump_recorder::on_instruction_pre(
    w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  (void) event;

  if (engine_ && !engine_->config().dump_on_entry && !engine_->dump_completed()) {
    engine_->dump_once(ctx, vm, gpr, fpr);
    return QBDI::VMAction::STOP;
  }

  return QBDI::VMAction::CONTINUE;
}

bool dump_recorder::dump_completed() const { return engine_ ? engine_->dump_completed() : false; }

} // namespace w1dump
