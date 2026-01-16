#include "rewind_tracer.hpp"

namespace w1rewind {

rewind_instruction_tracer::rewind_instruction_tracer(
    rewind_config config, std::shared_ptr<w1::rewind::trace_writer> writer
)
    : recorder_(std::move(config), std::move(writer)) {}

void rewind_instruction_tracer::on_thread_start(w1::trace_context& ctx, const w1::thread_event& event) {
  recorder_.on_thread_start(ctx, event);
}

void rewind_instruction_tracer::on_instruction_post(
    w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  recorder_.on_instruction_post(ctx, event, vm, gpr, fpr);
}

void rewind_instruction_tracer::on_memory(
    w1::trace_context& ctx, const w1::memory_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  recorder_.on_memory(ctx, event, vm, gpr, fpr);
}

void rewind_instruction_tracer::on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event) {
  recorder_.on_thread_stop(ctx, event);
}

rewind_block_tracer::rewind_block_tracer(rewind_config config, std::shared_ptr<w1::rewind::trace_writer> writer)
    : recorder_(std::move(config), std::move(writer)) {}

void rewind_block_tracer::on_thread_start(w1::trace_context& ctx, const w1::thread_event& event) {
  recorder_.on_thread_start(ctx, event);
}

void rewind_block_tracer::on_basic_block_entry(
    w1::trace_context& ctx, const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  recorder_.on_basic_block_entry(ctx, event, vm, state, gpr, fpr);
}

void rewind_block_tracer::on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event) {
  recorder_.on_thread_stop(ctx, event);
}

} // namespace w1rewind
