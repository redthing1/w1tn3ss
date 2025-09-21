#include "threadtest_tracer.hpp"

namespace threadtest {

threadtest_tracer::threadtest_tracer(
    threadtest_config config, uint64_t thread_id, std::string thread_name, redlog::logger log
)
    : config_(std::move(config)), thread_id_(thread_id), thread_name_(std::move(thread_name)), log_(std::move(log)) {}

bool threadtest_tracer::initialize(QBDI::VM& vm) {
  vm_ = &vm;
  basic_blocks_.store(0, std::memory_order_relaxed);

  basic_block_event_ = vm.addVMEventCB(QBDI::BASIC_BLOCK_ENTRY, &threadtest_tracer::handle_basic_block_entry, this);

  if (basic_block_event_ == QBDI::INVALID_EVENTID) {
    log_.err("failed to register basic block callback", redlog::field("thread_id", thread_id_));
    vm_ = nullptr;
    return false;
  }

  log_.dbg(
      "registered basic block callback", redlog::field("thread_id", thread_id_),
      redlog::field("event_id", basic_block_event_)
  );

  return true;
}

void threadtest_tracer::shutdown() {
  uint64_t blocks = basic_blocks_.load(std::memory_order_relaxed);
  log_.inf("thread tracer shutdown", redlog::field("thread_id", thread_id_), redlog::field("basic_blocks", blocks));

  vm_ = nullptr;
  basic_block_event_ = QBDI::INVALID_EVENTID;
}

QBDI::VMAction threadtest_tracer::handle_basic_block_entry(
    QBDI::VMInstanceRef, const QBDI::VMState* state, QBDI::GPRState*, QBDI::FPRState*, void* data
) {
  auto* self = static_cast<threadtest_tracer*>(data);
  if (!self) {
    return QBDI::VMAction::CONTINUE;
  }

  self->on_basic_block(state);
  return QBDI::VMAction::CONTINUE;
}

void threadtest_tracer::on_basic_block(const QBDI::VMState* state) {
  if (!state) {
    return;
  }

  uint64_t count = basic_blocks_.fetch_add(1, std::memory_order_relaxed) + 1;

  if (config_.verbose >= 2) {
    if (count <= 5 || (count % 100) == 0) {
      log_.vrb(
          "basic block", redlog::field("thread_id", thread_id_), redlog::field("name", thread_name_),
          redlog::field("count", count), redlog::field("start", "0x%08x", state->basicBlockStart),
          redlog::field("end", "0x%08x", state->basicBlockEnd)
      );
    }
  } else if (config_.verbose >= 1 && count == 1) {
    log_.inf(
        "first basic block", redlog::field("thread_id", thread_id_), redlog::field("name", thread_name_),
        redlog::field("start", "0x%08x", state->basicBlockStart), redlog::field("end", "0x%08x", state->basicBlockEnd)
    );
  }
}

} // namespace threadtest
