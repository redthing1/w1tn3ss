#pragma once

#include <QBDI.h>
#include <w1tn3ss/engine/tracer_engine.hpp>
#include <redlog.hpp>

#include "memory_collector.hpp"
#include "memory_config.hpp"

namespace w1mem {

class memory_tracer {
public:
  explicit memory_tracer(const memory_config& config);

  bool initialize(w1::tracer_engine<memory_tracer>& engine);
  void shutdown();
  const char* get_name() const { return "w1mem"; }

  // required callbacks for tracer_engine
  QBDI::VMAction on_instruction_postinst(QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr);

  // statistics access
  const memory_stats& get_stats() const;
  size_t get_trace_size() const;
  void export_report() const;

private:
  memory_config config_;
  memory_collector collector_;
  redlog::logger log_ = redlog::get_logger("w1mem.tracer");
  bool memory_recording_enabled_;
};

} // namespace w1mem