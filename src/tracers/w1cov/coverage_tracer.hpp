#pragma once

#include <mutex>
#include <unordered_map>
#include <unordered_set>

#include <QBDI.h>
#include <w1tn3ss/engine/tracer_engine.hpp>
#include <w1tn3ss/util/module_discovery.hpp>

#include "coverage_collector.hpp"
#include "coverage_config.hpp"

namespace w1cov {

class coverage_tracer {
public:
  explicit coverage_tracer(const coverage_config& config);

  bool initialize(w1::tracer_engine<coverage_tracer>& engine);
  void shutdown();
  const char* get_name() const { return "w1cov"; }

  QBDI::VMAction on_basic_block_entry(
      QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );

private:
  coverage_config config_;
  coverage_collector collector_;
  w1::util::module_discovery discoverer_;
  std::unordered_set<QBDI::rword> allowed_module_bases_;
  std::unordered_map<QBDI::rword, uint16_t> module_base_to_id_;
  std::mutex rescan_mutex_;

  void update_module_filter();
  bool should_trace_module(const w1::util::module_info& mod) const;
  void handle_unknown_module_rescan(w1::tracer_engine<coverage_tracer>& engine);
};

} // namespace w1cov