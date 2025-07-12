#pragma once

#include <QBDI.h>
#include <w1tn3ss/engine/tracer_engine.hpp>
#include <redlog.hpp>

#include "trace_collector.hpp"
#include "trace_config.hpp"

namespace w1trace {

class trace_tracer {
public:
  explicit trace_tracer(const trace_config& config);

  bool initialize(w1::tracer_engine<trace_tracer>& engine);
  void shutdown();
  const char* get_name() const { return "w1trace"; }

  QBDI::VMAction on_instruction_preinst(QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr);

  // Statistics access
  size_t get_instruction_count() const;
  size_t get_flush_count() const;
  size_t get_buffer_usage() const;
  void print_statistics() const;

  // Collector access for manual flush
  const trace_collector& get_collector() const;
  trace_collector& get_collector();

private:
  trace_config config_;
  trace_collector collector_;
  redlog::logger log_;
};

} // namespace w1trace