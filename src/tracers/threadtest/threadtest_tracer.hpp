#pragma once

#include <atomic>

#include <QBDI.h>
#include <redlog.hpp>

#include <w1tn3ss/engine/tracer_engine.hpp>

#include "threadtest_config.hpp"

namespace threadtest {

struct thread_context;

class threadtest_tracer {
public:
  threadtest_tracer(const threadtest_config& config, thread_context& context);

  bool initialize(w1::tracer_engine<threadtest_tracer>& engine);
  void shutdown();

  const char* get_name() const { return "threadtest"; }

  QBDI::VMAction on_basic_block_entry(
      QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );

private:
  const threadtest_config* config_;
  thread_context* context_;
  redlog::logger log_ = redlog::get_logger("threadtest.tracer");

  std::atomic<uint64_t> block_counter_ = 0;
};

} // namespace threadtest
