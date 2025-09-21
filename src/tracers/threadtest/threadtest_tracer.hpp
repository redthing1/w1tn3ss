#pragma once

#include <atomic>
#include <string>
#include <string_view>

#include <QBDI.h>
#include <redlog.hpp>

#include "threadtest_config.hpp"

namespace threadtest {

class threadtest_tracer {
public:
  threadtest_tracer(threadtest_config config, uint64_t thread_id, std::string thread_name, redlog::logger log);

  bool initialize(QBDI::VM& vm);
  void shutdown();

  uint64_t basic_block_count() const { return basic_blocks_.load(std::memory_order_relaxed); }

private:
  static QBDI::VMAction handle_basic_block_entry(
      QBDI::VMInstanceRef vm_ref, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data
  );

  void on_basic_block(const QBDI::VMState* state);

  threadtest_config config_;
  uint64_t thread_id_ = 0;
  std::string thread_name_;
  redlog::logger log_ = redlog::get_logger("threadtest.tracer");

  std::atomic<uint64_t> basic_blocks_{0};
  QBDI::VM* vm_ = nullptr;
  uint32_t basic_block_event_ = QBDI::INVALID_EVENTID;
};

} // namespace threadtest
