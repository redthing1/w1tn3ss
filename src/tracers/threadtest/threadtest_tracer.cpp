#include "threadtest_tracer.hpp"

#include <utility>

namespace threadtest {

threadtest_tracer::threadtest_tracer(threadtest_config config) : config_(std::move(config)) {
  log_.inf("threadtest tracer created", redlog::field("verbose", config_.verbose));
}

void threadtest_tracer::on_thread_start(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  thread_name_ = event.name ? event.name : "";
  if (config_.verbose >= 1) {
    log_.inf(
        "thread started", redlog::field("thread_id", event.thread_id), redlog::field("name", thread_name_)
    );
  }
}

void threadtest_tracer::on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  log_.inf(
      "thread stopped", redlog::field("thread_id", event.thread_id), redlog::field("name", thread_name_),
      redlog::field("basic_blocks", basic_blocks_)
  );
}

QBDI::VMAction threadtest_tracer::on_basic_block_entry(
    w1::trace_context& ctx, const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  (void) ctx;
  (void) vm;
  (void) state;
  (void) gpr;
  (void) fpr;

  uint64_t count = ++basic_blocks_;
  uint64_t end = event.size > 0 ? (event.address + event.size) : event.address;

  if (config_.verbose >= 2) {
    if (count <= 5 || (count % 100) == 0) {
      log_.vrb(
          "basic block", redlog::field("thread_id", event.thread_id), redlog::field("name", thread_name_),
          redlog::field("count", count), redlog::field("start", "0x%llx", event.address),
          redlog::field("end", "0x%llx", end)
      );
    }
  } else if (config_.verbose >= 1 && count == 1) {
    log_.inf(
        "first basic block", redlog::field("thread_id", event.thread_id), redlog::field("name", thread_name_),
        redlog::field("start", "0x%llx", event.address), redlog::field("end", "0x%llx", end)
    );
  }

  return QBDI::VMAction::CONTINUE;
}

} // namespace threadtest
