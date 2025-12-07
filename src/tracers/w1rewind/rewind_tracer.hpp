#pragma once

#include <memory>
#include <string>
#include <vector>

#include <QBDI.h>
#include <redlog.hpp>

#include "rewind_config.hpp"

#include <w1tn3ss/util/register_capture.hpp>
#include <w1tn3ss/runtime/rewind/trace_sink.hpp>
#include <w1tn3ss/runtime/rewind/trace_types.hpp>
#include <w1tn3ss/runtime/rewind/trace_validator.hpp>

namespace w1rewind {

class rewind_tracer {
public:
  rewind_tracer(
      rewind_config config, w1::rewind::trace_sink_ptr sink, w1::rewind::trace_validator_ptr validator,
      uint64_t thread_id, std::string thread_name, redlog::logger log
  );

  bool initialize(QBDI::VM& vm);
  void shutdown();

private:
  static QBDI::VMAction on_instruction(
      QBDI::VMInstanceRef vm_ref, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data
  );

  QBDI::VMAction handle_instruction(QBDI::GPRState* gpr, QBDI::FPRState* fpr);
  void capture_register_deltas(const QBDI::GPRState* gpr, w1::rewind::trace_event& event);
  void capture_full_registers(const QBDI::GPRState* gpr, w1::rewind::trace_event& event);
  void capture_memory_accesses(w1::rewind::trace_event& event);
  void maybe_emit_boundary_event(const QBDI::GPRState* gpr, uint64_t address, uint32_t size);
  void emit_boundary_event(const QBDI::GPRState* gpr, uint64_t address, uint32_t size);
  void log_progress();

  rewind_config config_;
  w1::rewind::trace_sink_ptr sink_;
  w1::rewind::trace_validator_ptr validator_;
  uint64_t thread_id_ = 0;
  std::string thread_name_;
  redlog::logger log_ = redlog::get_logger("w1rewind.tracer");

  QBDI::VM* vm_ = nullptr;
  uint32_t instruction_callback_id_ = QBDI::INVALID_EVENTID;
  bool memory_recording_enabled_ = false;
  uint64_t sequence_ = 0;
  uint64_t instruction_count_ = 0;
  uint64_t boundary_counter_ = 0;
  uint64_t instructions_since_boundary_ = 0;
  bool have_last_register_state_ = false;
  w1::util::register_state last_register_state_;
  bool stop_requested_ = false;
  bool validation_failed_ = false;
};

} // namespace w1rewind
