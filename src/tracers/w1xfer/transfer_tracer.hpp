#pragma once

#include <QBDI.h>
#include <redlog.hpp>
#include <w1tn3ss/engine/tracer_engine.hpp>

#include "transfer_collector.hpp"
#include "transfer_config.hpp"

namespace w1xfer {

class transfer_tracer {
public:
  explicit transfer_tracer(const transfer_config& config);

  bool initialize(w1::tracer_engine<transfer_tracer>& engine);
  void shutdown();
  const char* get_name() const { return "w1xfer"; }

  // exec transfer callbacks - these match the signatures expected by tracer_engine
  QBDI::VMAction on_exec_transfer_call(
      QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  QBDI::VMAction on_exec_transfer_return(
      QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );

  // statistics access
  const transfer_stats& get_stats() const;
  size_t get_trace_size() const;
  void export_report() const;

private:
  transfer_config config_;
  transfer_collector collector_;
  redlog::logger log_ = redlog::get_logger("w1.transfer_tracer");
};

} // namespace w1xfer