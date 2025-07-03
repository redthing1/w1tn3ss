#pragma once

#include <w1tn3ss/util/module_scanner.hpp>
#include <w1tn3ss/util/module_range_index.hpp>
#include "coverage_config.hpp"
#include "coverage_collector.hpp"
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <optional>
#include <type_traits>
#include <QBDI.h>
#include <redlog.hpp>

namespace w1cov {

/**
 * @brief specialized module tracker optimized for coverage tracing
 * @details replaces multiple data structures in coverage_tracer with single clean api.
 * provides hot path optimization with visitor pattern and handles rare rescanning.
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

  // module base address -> module id mapping
  std::unordered_map<QBDI::rword, uint16_t> base_to_module_id_;

  // thread safety - shared for reads, exclusive for rescanning
  mutable std::shared_mutex index_mutex_;
  mutable std::mutex rescan_mutex_;

  redlog::logger log_ = redlog::get_logger("w1cov.module_tracker");

  // filtering logic
  bool should_trace_module(const w1::util::module_info& mod) const;

  // index rebuilding
  void rebuild_index_from_modules(std::vector<w1::util::module_info> modules);
  std::unordered_set<QBDI::rword> get_known_module_bases() const;
};

template <typename Visitor>
bool coverage_module_tracker::visit_traced_module(QBDI::rword address, Visitor&& visitor) const {
  static_assert(
      std::is_invocable_v<Visitor, const w1::util::module_info&, uint16_t>,
      "visitor must be callable with (const module_info&, uint16_t)"
  );

  std::shared_lock<std::shared_mutex> lock(index_mutex_);

  return index_.visit_containing(address, [&](const w1::util::module_info& mod) {
    // check if this module is being traced
    if (auto it = base_to_module_id_.find(mod.base_address); it != base_to_module_id_.end()) {
      visitor(mod, it->second);
      return true;
    }
    return false;
  });
}

template <typename Visitor> bool coverage_module_tracker::try_rescan_and_visit(QBDI::rword address, Visitor&& visitor) {
  static_assert(
      std::is_invocable_v<Visitor, const w1::util::module_info&, uint16_t>,
      "visitor must be callable with (const module_info&, uint16_t)"
  );

  // non-blocking attempt to acquire rescan lock
  std::unique_lock<std::mutex> rescan_lock(rescan_mutex_, std::try_to_lock);
  if (!rescan_lock.owns_lock()) {
    log_.dbg("rescan already in progress, skipping", redlog::field("address", "0x%08x", address));
    return false;
  }

  log_.vrb("attempting module rescan", redlog::field("address", "0x%08x", address));

  try {
    // scan for new modules only
    auto known_bases = get_known_module_bases();
    auto new_modules = scanner_.scan_new_modules(known_bases);

    if (new_modules.empty()) {
      log_.dbg("no new modules discovered during rescan");
      return false;
    }

    // filter and add new modules to collector
    std::vector<w1::util::module_info> modules_to_add;
    for (const auto& mod : new_modules) {
      if (should_trace_module(mod)) {
        modules_to_add.push_back(mod);
      }
    }

    if (modules_to_add.empty()) {
      log_.dbg("no new traced modules after filtering", redlog::field("discovered_modules", new_modules.size()));
      return false;
    }

    // add new modules to collector and update mapping
    std::unordered_map<QBDI::rword, uint16_t> new_mappings;
    for (const auto& mod : modules_to_add) {
      uint16_t module_id = collector_->add_module(mod);
      new_mappings[mod.base_address] = module_id;

      log_.dbg(
          "added new traced module", redlog::field("module_name", mod.name), redlog::field("module_id", module_id),
          redlog::field("base_address", "0x%08x", mod.base_address)
      );
    }

    // rebuild complete index with all current modules
    auto all_current_modules = scanner_.scan_executable_modules();
    std::vector<w1::util::module_info> traced_modules;

    for (const auto& mod : all_current_modules) {
      if (should_trace_module(mod)) {
        traced_modules.push_back(mod);
      }
    }

    // rebuild index and update mappings atomically
    {
      std::unique_lock<std::shared_mutex> index_lock(index_mutex_);

      // update base_to_module_id with new mappings
      base_to_module_id_.insert(new_mappings.begin(), new_mappings.end());

      // rebuild index
      index_ = w1::util::module_range_index(std::move(traced_modules));
    }

    log_.inf(
        "rescan completed successfully", redlog::field("new_traced_modules", modules_to_add.size()),
        redlog::field("total_traced_modules", traced_module_count())
    );

    // try the lookup again with updated index
    return visit_traced_module(address, std::forward<Visitor>(visitor));

  } catch (const std::exception& e) {
    log_.err("exception during module rescan", redlog::field("error", e.what()));
    return false;
  }
}

} // namespace w1cov