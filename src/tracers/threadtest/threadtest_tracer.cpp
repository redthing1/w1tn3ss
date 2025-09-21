#include "threadtest_tracer.hpp"

#include "thread_context.hpp"

namespace threadtest {

threadtest_tracer::threadtest_tracer(const threadtest_config& config, thread_context& context)
    : config_(&config), context_(&context) {}

bool threadtest_tracer::initialize(w1::tracer_engine<threadtest_tracer>& engine) {
  if (!context_) {
    log_.err("thread context not set");
    return false;
  }

  QBDI::VM* vm = engine.get_vm();
  if (!vm) {
    log_.err("vm instance is null");
    return false;
  }

  block_counter_.store(0, std::memory_order_relaxed);
  context_->basic_blocks = 0;

  uint32_t event_id = vm->addVMEventCB(
      QBDI::BASIC_BLOCK_ENTRY,
      [](QBDI::VMInstanceRef vm_ref, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr,
         void* data) -> QBDI::VMAction {
        auto* self = static_cast<threadtest_tracer*>(data);
        return self->on_basic_block_entry(vm_ref, state, gpr, fpr);
      },
      this
  );

  if (event_id == QBDI::INVALID_EVENTID) {
    log_.err("failed to register basic block callback");
    return false;
  }

  log_.inf(
      "thread tracer initialized", redlog::field("thread_id", context_->thread_id), redlog::field("event_id", event_id)
  );

  return true;
}

void threadtest_tracer::shutdown() {
  uint64_t blocks = context_ ? context_->basic_blocks : 0;
  log_.inf(
      "thread tracer shutdown", redlog::field("thread_id", context_ ? context_->thread_id : 0),
      redlog::field("basic_blocks", blocks)
  );
}

QBDI::VMAction threadtest_tracer::on_basic_block_entry(
    QBDI::VMInstanceRef, const QBDI::VMState* state, QBDI::GPRState*, QBDI::FPRState*
) {
  if (!state || !context_) {
    return QBDI::VMAction::CONTINUE;
  }

  uint64_t count = block_counter_.fetch_add(1, std::memory_order_relaxed) + 1;
  context_->basic_blocks = count;

  if (config_ && config_->verbose >= 2) {
    if (count <= 5 || (count % 100) == 0) {
      context_->log.vrb(
          "basic block", redlog::field("thread_id", context_->thread_id), redlog::field("count", count),
          redlog::field("start", "0x%08x", state->basicBlockStart), redlog::field("end", "0x%08x", state->basicBlockEnd)
      );
    }
  } else if (config_ && config_->verbose >= 1 && count == 1) {
    context_->log.inf(
        "first basic block", redlog::field("thread_id", context_->thread_id),
        redlog::field("start", "0x%08x", state->basicBlockStart), redlog::field("end", "0x%08x", state->basicBlockEnd)
    );
  }

  return QBDI::VMAction::CONTINUE;
}

} // namespace threadtest
