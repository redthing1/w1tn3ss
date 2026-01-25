#include "script_tracer.hpp"

#include "w1instrument/tracer/event.hpp"

#include <utility>

namespace w1::tracers::script {

script_tracer::script_tracer() : logger_(redlog::get_logger("w1script.thread")) {}

script_tracer::script_tracer(std::shared_ptr<script_engine> engine, script_config config)
    : config_(std::move(config)), logger_(redlog::get_logger("w1script.thread")) {
  (void) engine;
}

bool script_tracer::ensure_initialized(w1::trace_context& ctx, const w1::thread_event* event) {
  if (initialized_) {
    return true;
  }
  if (failed_) {
    return false;
  }

  if (config_.script_path.empty()) {
    config_ = script_config::from_environment();
  }

  if (!config_.is_valid()) {
    logger_.err("invalid configuration", redlog::field("script_path", config_.script_path));
    failed_ = true;
    return false;
  }

  QBDI::VM* vm = ctx.vm();
  if (!vm) {
    logger_.err("vm instance is null");
    failed_ = true;
    return false;
  }

  std::string thread_name = "main";
  if (event && event->name) {
    thread_name = event->name;
  }

  ctx.modules().refresh();

  context_ = std::make_unique<runtime::script_context>(
      vm, config_, &ctx.modules(), &ctx.memory(), ctx.thread_id(), thread_name
  );
  runtime_ = std::make_unique<runtime::lua_runtime>(*context_);

  if (!runtime_->initialize()) {
    logger_.err("lua runtime initialization failed");
    runtime_.reset();
    context_.reset();
    failed_ = true;
    return false;
  }

  logger_.inf("script runtime initialized", redlog::field("script", config_.script_path));
  initialized_ = true;
  return true;
}

QBDI::VMAction script_tracer::on_thread_start(w1::trace_context& ctx, const w1::thread_event& event) {
  if (!ensure_initialized(ctx, &event)) {
    return QBDI::VMAction::CONTINUE;
  }

  return runtime_->dispatch_thread_start(event);
}

QBDI::VMAction script_tracer::on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  if (!initialized_ || !runtime_) {
    return QBDI::VMAction::CONTINUE;
  }

  QBDI::VMAction action = runtime_->dispatch_thread_stop(event);
  runtime_->shutdown();
  runtime_.reset();
  context_.reset();
  initialized_ = false;
  failed_ = false;

  return action;
}

QBDI::VMAction script_tracer::on_vm_start(
    w1::trace_context& ctx, const w1::sequence_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  if (!ensure_initialized(ctx, nullptr)) {
    return QBDI::VMAction::CONTINUE;
  }

  return runtime_->dispatch_vm_start(event, vm, state, gpr, fpr);
}

QBDI::VMAction script_tracer::on_vm_stop(
    w1::trace_context& ctx, const w1::sequence_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  (void) ctx;
  if (!initialized_ || !runtime_) {
    return QBDI::VMAction::CONTINUE;
  }

  return runtime_->dispatch_vm_stop(event, vm, state, gpr, fpr);
}

QBDI::VMAction script_tracer::on_instruction_pre(
    w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  if (!ensure_initialized(ctx, nullptr)) {
    return QBDI::VMAction::CONTINUE;
  }

  return runtime_->dispatch_instruction_pre(event, vm, gpr, fpr);
}

QBDI::VMAction script_tracer::on_instruction_post(
    w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  if (!ensure_initialized(ctx, nullptr)) {
    return QBDI::VMAction::CONTINUE;
  }

  return runtime_->dispatch_instruction_post(event, vm, gpr, fpr);
}

QBDI::VMAction script_tracer::on_basic_block_entry(
    w1::trace_context& ctx, const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  if (!ensure_initialized(ctx, nullptr)) {
    return QBDI::VMAction::CONTINUE;
  }

  return runtime_->dispatch_basic_block_entry(event, vm, state, gpr, fpr);
}

QBDI::VMAction script_tracer::on_basic_block_exit(
    w1::trace_context& ctx, const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  if (!ensure_initialized(ctx, nullptr)) {
    return QBDI::VMAction::CONTINUE;
  }

  return runtime_->dispatch_basic_block_exit(event, vm, state, gpr, fpr);
}

QBDI::VMAction script_tracer::on_exec_transfer_call(
    w1::trace_context& ctx, const w1::exec_transfer_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  if (!ensure_initialized(ctx, nullptr)) {
    return QBDI::VMAction::CONTINUE;
  }

  return runtime_->dispatch_exec_transfer_call(event, vm, state, gpr, fpr);
}

QBDI::VMAction script_tracer::on_exec_transfer_return(
    w1::trace_context& ctx, const w1::exec_transfer_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  if (!ensure_initialized(ctx, nullptr)) {
    return QBDI::VMAction::CONTINUE;
  }

  return runtime_->dispatch_exec_transfer_return(event, vm, state, gpr, fpr);
}

QBDI::VMAction script_tracer::on_memory(
    w1::trace_context& ctx, const w1::memory_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  if (!ensure_initialized(ctx, nullptr)) {
    return QBDI::VMAction::CONTINUE;
  }

  return runtime_->dispatch_memory(event, vm, gpr, fpr);
}

} // namespace w1::tracers::script
