#pragma once

#include <QBDI.h>
#include <w1tn3ss/engine/tracer_engine.hpp>
#include <redlog.hpp>

#include "instruction_collector.hpp"
#include "instruction_config.hpp"

namespace w1inst {

class instruction_tracer {
public:
  explicit instruction_tracer(const instruction_config& config);

  bool initialize(w1::tracer_engine<instruction_tracer>& engine);
  void shutdown();
  const char* get_name() const { return "w1inst"; }

  // instruction callback for mnemonic filtering
  QBDI::VMAction on_instruction_preinst(QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr);

  // statistics access
  const mnemonic_stats& get_stats() const;
  size_t get_trace_size() const;
  void export_report() const;

private:
  instruction_config config_;
  mnemonic_collector collector_;
  redlog::logger log_ = redlog::get_logger("w1inst.tracer");
};

} // namespace w1inst