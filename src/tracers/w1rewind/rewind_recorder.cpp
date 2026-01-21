#include "rewind_recorder.hpp"

#include <optional>

#include "w1runtime/register_capture.hpp"

namespace w1rewind {

namespace {

std::optional<w1::util::register_state> capture_registers(const QBDI::GPRState* gpr) {
  if (!gpr) {
    return std::nullopt;
  }
  return w1::util::register_capturer::capture(gpr);
}

w1::instruction_event patch_instruction_event(const w1::instruction_event& event, QBDI::VMInstanceRef vm) {
  w1::instruction_event adjusted = event;
  if ((adjusted.address == 0 || adjusted.size == 0) && vm) {
    if (const auto* analysis = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION)) {
      adjusted.address = analysis->address;
      adjusted.size = analysis->instSize;
    }
  }
  return adjusted;
}

} // namespace

rewind_recorder::rewind_recorder(rewind_config config, std::shared_ptr<w1::rewind::trace_record_sink> sink)
    : engine_(std::move(config), std::move(sink)) {}

void rewind_recorder::on_thread_start(w1::trace_context& ctx, const w1::thread_event& event) {
  engine_.on_thread_start(ctx, event);
}

void rewind_recorder::on_basic_block_entry(
    w1::trace_context& ctx, const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  (void) vm;
  (void) state;
  (void) fpr;

  auto regs = capture_registers(gpr);
  engine_.on_basic_block_entry(ctx, event, regs ? &*regs : nullptr);
}

void rewind_recorder::on_instruction_post(
    w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  (void) fpr;

  auto regs = capture_registers(gpr);
  auto adjusted = patch_instruction_event(event, vm);
  engine_.on_instruction_post(ctx, adjusted, regs ? &*regs : nullptr);
}

void rewind_recorder::on_memory(
    w1::trace_context& ctx, const w1::memory_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  (void) vm;
  (void) fpr;

  auto regs = capture_registers(gpr);
  engine_.on_memory(ctx, event, regs ? &*regs : nullptr);
}

void rewind_recorder::on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event) {
  engine_.on_thread_stop(ctx, event);
}

} // namespace w1rewind
