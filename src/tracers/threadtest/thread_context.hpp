#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include <redlog.hpp>
#include <w1tn3ss/engine/tracer_engine.hpp>

namespace threadtest {

class threadtest_tracer;
struct threadtest_config;

struct thread_context {
  thread_context();
  ~thread_context();

  uint64_t thread_id = 0;
  std::string thread_name;

  std::unique_ptr<threadtest_tracer> tracer;
  std::unique_ptr<w1::tracer_engine<threadtest_tracer>> engine;

  uint64_t basic_blocks = 0;
  uint64_t instructions = 0;

  redlog::logger log = redlog::get_logger("threadtest.thread");
};

} // namespace threadtest
