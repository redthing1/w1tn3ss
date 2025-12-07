#pragma once

#include <memory>
#include <string>
#include <string_view>

#include <QBDI.h>
#include <redlog.hpp>

#include <w1tn3ss/engine/instrumentation_manager.hpp>
#include <w1tn3ss/runtime/threading/thread_runtime.hpp>

#include "rewind_config.hpp"
#include "rewind_tracer.hpp"

#include <w1tn3ss/runtime/rewind/trace_sink.hpp>

namespace w1rewind {

class rewind_session : public w1::runtime::threading::thread_tracer_session {
public:
  rewind_session(
      rewind_config config, w1::rewind::trace_sink_ptr sink, w1::rewind::trace_validator_ptr validator,
      uint64_t thread_id, std::string thread_name, redlog::logger log
  );

  bool initialize_main(QBDI::VMInstanceRef vm) override;
  bool initialize_worker() override;
  w1::runtime::threading::thread_result_t run_worker(
      w1::runtime::threading::thread_start_fn start_routine, void* arg
  ) override;
  void shutdown() override;
  const char* tracer_name() const override { return "w1rewind"; }

private:
  bool setup_tracer();
  bool apply_instrumentation();

  rewind_config config_;
  w1::rewind::trace_sink_ptr sink_;
  w1::rewind::trace_validator_ptr validator_;
  uint64_t thread_id_ = 0;
  std::string thread_name_;
  redlog::logger log_;

  std::unique_ptr<QBDI::VM> owned_vm_;
  QBDI::VM* vm_ = nullptr;

  std::unique_ptr<rewind_tracer> tracer_;
};

class rewind_session_factory : public w1::runtime::threading::thread_session_factory {
public:
  rewind_session_factory(rewind_config config, w1::rewind::trace_sink_ptr sink, w1::rewind::trace_validator_ptr validator);

  std::unique_ptr<w1::runtime::threading::thread_tracer_session> create_for_main_thread(
      uint64_t thread_id, std::string_view thread_name, redlog::logger log
  ) override;

  std::unique_ptr<w1::runtime::threading::thread_tracer_session> create_for_worker_thread(
      uint64_t thread_id, std::string_view thread_name, redlog::logger log
  ) override;

private:
  rewind_config config_;
  w1::rewind::trace_sink_ptr sink_;
  w1::rewind::trace_validator_ptr validator_;
};

} // namespace w1rewind
