#pragma once

#include <memory>
#include <string>

#include <QBDI.h>
#include <redlog.hpp>

#include <w1tn3ss/runtime/threading/thread_runtime.hpp>

#include "coverage_config.hpp"
#include "coverage_runtime.hpp"
#include "coverage_thread_tracer.hpp"

namespace w1cov {

class coverage_thread_session : public w1::runtime::threading::thread_tracer_session {
public:
  coverage_thread_session(
      coverage_runtime& runtime, coverage_config config, uint64_t thread_id, std::string thread_name, redlog::logger log
  );

  bool initialize_main(QBDI::VMInstanceRef vm) override;
  bool initialize_worker() override;
  w1::runtime::threading::thread_result_t run_worker(
      w1::runtime::threading::thread_start_fn start_routine, void* arg
  ) override;
  void shutdown() override;
  const char* tracer_name() const override { return "w1cov"; }

private:
  bool setup_tracer();
  bool apply_instrumentation();

  coverage_runtime& runtime_;
  coverage_config config_;
  uint64_t thread_id_ = 0;
  std::string thread_name_;
  redlog::logger log_;

  std::unique_ptr<QBDI::VM> owned_vm_;
  QBDI::VM* vm_ = nullptr;

  std::unique_ptr<coverage_thread_tracer> tracer_;
};

class coverage_thread_session_factory : public w1::runtime::threading::thread_session_factory {
public:
  coverage_thread_session_factory(coverage_runtime& runtime, coverage_config config);

  std::unique_ptr<w1::runtime::threading::thread_tracer_session> create_for_main_thread(
      uint64_t thread_id, std::string_view thread_name, redlog::logger log
  ) override;

  std::unique_ptr<w1::runtime::threading::thread_tracer_session> create_for_worker_thread(
      uint64_t thread_id, std::string_view thread_name, redlog::logger log
  ) override;

private:
  coverage_runtime& runtime_;
  coverage_config config_;
};

} // namespace w1cov
