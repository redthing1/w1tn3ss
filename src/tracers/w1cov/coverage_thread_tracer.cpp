#include "coverage_thread_tracer.hpp"

#include <utility>

#include <w1tn3ss/util/register_access.hpp>

namespace w1cov {

coverage_thread_tracer::coverage_thread_tracer(
    coverage_runtime& runtime, coverage_config config, uint64_t thread_id, std::string thread_name, redlog::logger log
)
    : runtime_(runtime), config_(std::move(config)), thread_id_(thread_id), thread_name_(std::move(thread_name)),
      log_(std::move(log)), buffer_(runtime.create_thread_buffer()) {}

bool coverage_thread_tracer::initialize(QBDI::VM& vm) {
  vm_ = &vm;

  if (config_.inst_trace) {
    instruction_event_id_ = vm.addCodeCB(QBDI::PREINST, coverage_thread_tracer::handle_instruction, this);
    if (instruction_event_id_ == QBDI::INVALID_EVENTID) {
      log_.err("failed to register instruction callback", redlog::field("thread_id", thread_id_));
      return false;
    }

    log_.dbg(
        "registered instruction callback", redlog::field("thread_id", thread_id_),
        redlog::field("callback_id", instruction_event_id_)
    );
  } else {
    basic_block_event_id_ = vm.addVMEventCB(QBDI::BASIC_BLOCK_ENTRY, coverage_thread_tracer::handle_basic_block, this);
    if (basic_block_event_id_ == QBDI::INVALID_EVENTID) {
      log_.err("failed to register basic block callback", redlog::field("thread_id", thread_id_));
      return false;
    }

    log_.dbg(
        "registered basic block callback", redlog::field("thread_id", thread_id_),
        redlog::field("callback_id", basic_block_event_id_)
    );
  }

  return true;
}

void coverage_thread_tracer::shutdown() {
  unregister_callbacks();

  uint64_t hit_total = 0;
  for (const auto& [_, entry] : buffer_.entries()) {
    hit_total += entry.hits;
  }

  log_.dbg(
      "merging coverage buffer", redlog::field("thread_id", thread_id_), redlog::field("blocks", buffer_.size()),
      redlog::field("hits", hit_total)
  );

  runtime_.merge_buffer(buffer_);
  buffer_.clear();
  vm_ = nullptr;
}

QBDI::VMAction coverage_thread_tracer::handle_basic_block(
    QBDI::VMInstanceRef, const QBDI::VMState* state, QBDI::GPRState*, QBDI::FPRState*, void* data
) {
  auto* tracer = static_cast<coverage_thread_tracer*>(data);
  return tracer ? tracer->on_basic_block(state) : QBDI::VMAction::CONTINUE;
}

QBDI::VMAction coverage_thread_tracer::handle_instruction(
    QBDI::VMInstanceRef vm_ref, QBDI::GPRState* gpr, QBDI::FPRState*, void* data
) {
  auto* tracer = static_cast<coverage_thread_tracer*>(data);
  return tracer ? tracer->on_instruction(vm_ref, gpr) : QBDI::VMAction::CONTINUE;
}

QBDI::VMAction coverage_thread_tracer::on_basic_block(const QBDI::VMState* state) {
  if (!state) {
    return QBDI::VMAction::CONTINUE;
  }

  QBDI::rword start = state->basicBlockStart;
  QBDI::rword end = state->basicBlockEnd;
  uint16_t size = static_cast<uint16_t>(end - start);

  runtime_.record_block(buffer_, start, size);
  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction coverage_thread_tracer::on_instruction(QBDI::VMInstanceRef, QBDI::GPRState* gpr) {
  if (!gpr) {
    return QBDI::VMAction::CONTINUE;
  }

  QBDI::rword pc = w1::registers::get_pc(gpr);
  if (pc == 0) {
    return QBDI::VMAction::CONTINUE;
  }

  runtime_.record_block(buffer_, pc, 1);
  return QBDI::VMAction::CONTINUE;
}

void coverage_thread_tracer::unregister_callbacks() {
  if (!vm_) {
    return;
  }

  if (basic_block_event_id_ != QBDI::INVALID_EVENTID) {
    if (vm_->deleteInstrumentation(basic_block_event_id_)) {
      log_.dbg(
          "removed basic block callback", redlog::field("thread_id", thread_id_),
          redlog::field("callback_id", basic_block_event_id_)
      );
    }
    basic_block_event_id_ = QBDI::INVALID_EVENTID;
  }

  if (instruction_event_id_ != QBDI::INVALID_EVENTID) {
    if (vm_->deleteInstrumentation(instruction_event_id_)) {
      log_.dbg(
          "removed instruction callback", redlog::field("thread_id", thread_id_),
          redlog::field("callback_id", instruction_event_id_)
      );
    }
    instruction_event_id_ = QBDI::INVALID_EVENTID;
  }
}

} // namespace w1cov
