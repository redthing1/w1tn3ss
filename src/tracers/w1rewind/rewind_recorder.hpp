#pragma once

#include <memory>

#include <QBDI.h>

#include "recording_engine.hpp"
#include "rewind_config.hpp"
#include "w1rewind/trace/record_sink.hpp"

namespace w1rewind {

class rewind_recorder {
public:
  rewind_recorder(rewind_config config, std::shared_ptr<w1::rewind::trace_record_sink> sink);

  void on_thread_start(w1::trace_context& ctx, const w1::thread_event& event);
  void on_basic_block_entry(
      w1::trace_context& ctx, const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  void on_instruction_post(
      w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );
  void on_memory(
      w1::trace_context& ctx, const w1::memory_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );
  void on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event);

private:
  recording_engine engine_;
};

} // namespace w1rewind
