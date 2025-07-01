#pragma once

#include <QBDI.h>
#include <w1tn3ss/engine/tracer_engine.hpp>

#include "coverage_collector.hpp"
#include "coverage_config.hpp"
#include "coverage_module_tracker.hpp"

namespace w1cov {

/**
 * @brief coverage tracer using optimized module tracking
 * @details simplified design using coverage_module_tracker for fast lookups
 * and integrated filtering. eliminates multiple data structures.
 */
class coverage_tracer {
public:
  explicit coverage_tracer(const coverage_config& config);

  bool initialize(w1::tracer_engine<coverage_tracer>& engine);
  void shutdown();
  const char* get_name() const { return "w1cov"; }

  QBDI::VMAction on_basic_block_entry(
      QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );

  // statistics access for standalone API
  size_t get_basic_block_count() const;
  size_t get_module_count() const;
  uint64_t get_total_hits() const;
  void print_statistics() const;

  // collector access for standalone export
  const coverage_collector& get_collector() const;

private:
  coverage_config config_;
  coverage_collector collector_;
  coverage_module_tracker module_tracker_;
};

} // namespace w1cov