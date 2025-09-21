#pragma once

#include <memory>
#include <string>
#include <vector>

#include <QBDI.h>
#include <redlog.hpp>

#include <w1tn3ss/engine/instrumentation_manager.hpp>
#include <w1tn3ss/runtime/threading/thread_runtime.hpp>

#include "threadtest_config.hpp"
#include "threadtest_tracer.hpp"

namespace threadtest {

class threadtest_session : public w1::runtime::threading::thread_tracer_session {
public:
  threadtest_session(threadtest_config config, uint64_t thread_id, std::string thread_name, redlog::logger log);

  bool initialize_main(QBDI::VMInstanceRef vm) override;
  bool initialize_worker() override;
  w1::runtime::threading::thread_result_t run_worker(
      w1::runtime::threading::thread_start_fn start_routine, void* arg
  ) override;
  void shutdown() override;
  const char* tracer_name() const override { return "threadtest"; }

private:
  bool setup_tracer();
  bool apply_instrumentation();

  threadtest_config config_;
  uint64_t thread_id_ = 0;
  std::string thread_name_;
  redlog::logger log_;

  std::unique_ptr<QBDI::VM> owned_vm_;
  QBDI::VM* vm_ = nullptr;

  std::unique_ptr<threadtest_tracer> tracer_;
};

class threadtest_session_factory : public w1::runtime::threading::thread_session_factory {
public:
  explicit threadtest_session_factory(threadtest_config config);

  std::unique_ptr<w1::runtime::threading::thread_tracer_session> create_for_main_thread(
      uint64_t thread_id, std::string_view thread_name, redlog::logger log
  ) override;

  std::unique_ptr<w1::runtime::threading::thread_tracer_session> create_for_worker_thread(
      uint64_t thread_id, std::string_view thread_name, redlog::logger log
  ) override;

private:
  threadtest_config config_;
};

} // namespace threadtest
