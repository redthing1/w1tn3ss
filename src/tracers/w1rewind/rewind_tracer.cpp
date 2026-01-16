#include "rewind_tracer.hpp"

namespace w1rewind {

rewind_tracer::rewind_tracer(rewind_config config, std::shared_ptr<w1::rewind::trace_writer> writer)
    : recorder_(std::move(config), std::move(writer)) {}

void rewind_tracer::on_thread_start(w1::trace_context& ctx, const w1::thread_event& event) {
  recorder_.on_thread_start(ctx, event);
}

void rewind_tracer::on_instruction_post(
    w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  recorder_.on_instruction_post(ctx, event, vm, gpr, fpr);
}

void rewind_tracer::on_memory(
    w1::trace_context& ctx, const w1::memory_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  recorder_.on_memory(ctx, event, vm, gpr, fpr);
}

void rewind_tracer::on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event) {
  recorder_.on_thread_stop(ctx, event);
}

} // namespace w1rewind
