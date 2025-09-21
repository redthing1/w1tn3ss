#pragma once

#include <string>

#include <QBDI.h>
#include <redlog.hpp>

#include "coverage_config.hpp"
#include "coverage_runtime.hpp"

namespace w1cov {

class coverage_thread_tracer {
public:
  coverage_thread_tracer(
      coverage_runtime& runtime, coverage_config config, uint64_t thread_id, std::string thread_name, redlog::logger log
  );

  bool initialize(QBDI::VM& vm);
  void shutdown();

private:
  static QBDI::VMAction handle_basic_block(
      QBDI::VMInstanceRef vm_ref, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data
  );

  static QBDI::VMAction handle_instruction(
      QBDI::VMInstanceRef vm_ref, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data
  );

  QBDI::VMAction on_basic_block(const QBDI::VMState* state);
  QBDI::VMAction on_instruction(QBDI::VMInstanceRef vm_ref, QBDI::GPRState* gpr);

  void unregister_callbacks();

  coverage_runtime& runtime_;
  coverage_config config_;
  uint64_t thread_id_ = 0;
  std::string thread_name_;
  redlog::logger log_;

  coverage_thread_buffer buffer_;
  QBDI::VM* vm_ = nullptr;
  uint32_t basic_block_event_id_ = QBDI::INVALID_EVENTID;
  uint32_t instruction_event_id_ = QBDI::INVALID_EVENTID;
};

} // namespace w1cov
