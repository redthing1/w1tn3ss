#pragma once

#include <w1tn3ss/util/module_scanner.hpp>
#include <w1tn3ss/util/module_range_index.hpp>
#include "coverage_config.hpp"
#include "coverage_collector.hpp"
#include <atomic>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <type_traits>
#include <QBDI.h>
#include <redlog.hpp>

namespace w1cov {

/**
 * @brief thin wrapper around module_range_index for coverage-specific functionality
 * @details provides coverage filtering and module id mapping on top of generic module tracking.
 * hot path is optimized for basic block entry with zero allocations.
 */
class coverage_module_tracker {
public:
  /**
   * @brief construct tracker with coverage configuration
   * @param config coverage configuration for module filtering
   */
  explicit coverage_module_tracker(const coverage_config& config);

  /**
   * @brief initialize tracker with collector, builds initial module index
   * @param collector coverage collector to register modules with
   * @details scans modules, applies filtering, and builds fast lookup index
   */
  void initialize(coverage_collector& collector);

  /**
   * @brief visit traced module at address using visitor pattern (hot path)
   * @param address memory address to query
   * @param visitor callable invoked with module_info and module_id if found
   * @return true if module found and visitor called, false otherwise
   * @note zero logging, zero allocations, optimized for basic block entry
   */
  template <typename Visitor> bool visit_traced_module(QBDI::rword address, Visitor&& visitor) const;

  /**
   * @brief attempt rescanning and visit module at address (rare path)
   * @param address memory address to query
   * @param visitor callable invoked with module_info and module_id if found
   * @return true if module found after rescanning, false otherwise
   * @note non-blocking, with logging and comprehensive error handling
   */
  template <typename Visitor> bool try_rescan_and_visit(QBDI::rword address, Visitor&& visitor);

  /**
   * @brief get count of currently traced modules
   * @return number of modules being traced
   */
  size_t traced_module_count() const;

private:
  const coverage_config& config_;
  w1::util::module_scanner scanner_;
  w1::util::module_range_index index_;
  coverage_collector* collector_;

  using module_map = std::unordered_map<QBDI::rword, uint16_t>;
  module_map module_map_;
  mutable std::shared_mutex map_mutex_;

  redlog::logger log_ = redlog::get_logger("w1cov.module_tracker");

  // coverage-specific filtering logic
  bool should_trace_module(const w1::util::module_info& mod) const;

  // rebuild traced modules with coverage filtering
  void rebuild_traced_modules();

  uint16_t ensure_module_registered(const w1::util::module_info& mod);
};

template <typename Visitor>
bool coverage_module_tracker::visit_traced_module(QBDI::rword address, Visitor&& visitor) const {
  static_assert(
      std::is_invocable_v<Visitor, const w1::util::module_info&, uint16_t>,
      "visitor must be callable with (const module_info&, uint16_t)"
  );

  std::shared_lock<std::shared_mutex> lock(map_mutex_);

  return index_.visit_containing(address, [&](const w1::util::module_info& mod) {
    auto it = module_map_.find(mod.base_address);
    if (it == module_map_.end()) {
      return false;
    }

    visitor(mod, it->second);
    return true;
  });
}

template <typename Visitor> bool coverage_module_tracker::try_rescan_and_visit(QBDI::rword address, Visitor&& visitor) {
  static_assert(
      std::is_invocable_v<Visitor, const w1::util::module_info&, uint16_t>,
      "visitor must be callable with (const module_info&, uint16_t)"
  );

  // delegate to generic index rescanning
  bool found = index_.try_rescan_and_visit(address, scanner_, [&](const w1::util::module_info& mod) {
    // check if this module should be traced
    if (should_trace_module(mod)) {
      uint16_t module_id = ensure_module_registered(mod);
      visitor(mod, module_id);
      return true;
    }
    return false;
  });

  return found;
}

} // namespace w1cov
