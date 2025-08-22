#pragma once

#include <QBDI.h>
#include <w1tn3ss/engine/tracer_engine.hpp>
#include <redlog.hpp>
#include <vector>
#include <string>

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

  // static callback for mnemonic events
  static QBDI::VMAction on_branch_mnemonic(
      QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data
  );

  // statistics access
  size_t get_instruction_count() const;
  const trace_stats& get_stats() const;
  void print_statistics() const;

  // collector access
  const trace_collector& get_collector() const;
  trace_collector& get_collector();

private:
  // register control flow callbacks
  bool register_control_flow_callbacks(QBDI::VM* vm);
  std::vector<std::string> get_architecture_mnemonics() const;

  trace_config config_;
  trace_collector collector_;
  redlog::logger log_;
  std::vector<uint32_t> callback_ids_;
};

} // namespace w1trace