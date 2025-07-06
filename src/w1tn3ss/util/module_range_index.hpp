#pragma once

#include "module_info.hpp"
#include "module_scanner.hpp"
#include "interval_tree.hpp"
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <shared_mutex>
#include <mutex>
#include <type_traits>
#include <QBDI.h>
#include <redlog.hpp>

namespace w1 {
namespace util {

/**
 * @brief fast address-to-module lookup using interval tree with dynamic rescanning
 * @details thread-safe for concurrent reads, supports dynamic module updates.
 * optimized for point queries with o(log n + k) complexity where k is typically 1.
 * hot path (visit_containing) is zero-allocation with minimal locking.
 */
class module_range_index {
public:
  /**
   * @brief construct empty index
   */
  module_range_index() = default;

  /**
   * @brief construct index from vector of modules
   * @param modules vector of module_info objects to index
   * @details sorts modules and builds interval tree. construction is o(n log n).
   */
  explicit module_range_index(std::vector<module_info> modules);

  /**
   * @brief find module containing the given address (hot path)
   * @param address memory address to query
   * @return pointer to module_info if found, nullptr otherwise
   * @note this method is noexcept and thread-safe, no logging
   */
  const module_info* find_containing(QBDI::rword address) const noexcept;

  /**
   * @brief visit module containing the given address using visitor pattern (hot path)
   * @param address memory address to query
   * @param visitor callable invoked with const module_info& if found
   * @return true if module found and visitor called, false otherwise
   * @note zero-allocation hot path optimization, no logging
   */
  template <typename Visitor> bool visit_containing(QBDI::rword address, Visitor&& visitor) const;

  /**
   * @brief attempt rescanning and visit module at address (cold path)
   * @param address memory address to query
   * @param scanner module scanner to use for rescanning
   * @param visitor callable invoked with const module_info& if found
   * @return true if module found after rescanning, false otherwise
   * @note non-blocking, with logging and comprehensive error handling
   */
  template <typename Visitor>
  bool try_rescan_and_visit(QBDI::rword address, module_scanner& scanner, Visitor&& visitor);

  /**
   * @brief rebuild index from new module list
   * @param modules new vector of modules to index
   * @details thread-safe, atomically replaces current index
   */
  void rebuild_from_modules(std::vector<module_info> modules);

  /**
   * @brief get set of all known module base addresses
   * @return unordered_set of base addresses
   */
  std::unordered_set<QBDI::rword> get_known_module_bases() const;

  /**
   * @brief visit all modules in the index
   * @param visitor callable invoked with const module_info& for each module
   */
  template <typename Visitor> void visit_all(Visitor&& visitor) const;

  /**
   * @brief find module by name (exact match)
   * @param name module name to search for
   * @return pointer to module_info if found, nullptr otherwise
   */
  const module_info* find_by_name(const std::string& name) const noexcept;

  /**
   * @brief check if index is empty
   * @return true if no modules indexed
   */
  bool empty() const noexcept;

  /**
   * @brief get number of indexed modules
   * @return count of modules in index
   */
  size_t size() const noexcept;

private:
  using module_interval = interval_tree::interval<QBDI::rword, module_info>;
  interval_tree::interval_tree<QBDI::rword, module_info> tree_;

  // name-based lookup cache
  std::unordered_map<std::string, const module_info*> name_index_;

  // thread safety - shared for reads, exclusive for updates
  mutable std::shared_mutex index_mutex_;
  mutable std::mutex rescan_mutex_;

  redlog::logger log_{"w1.module_range_index"};

  void build_name_index();
  void rebuild_internal(std::vector<module_info> modules);
};

template <typename Visitor> bool module_range_index::visit_containing(QBDI::rword address, Visitor&& visitor) const {
  static_assert(std::is_invocable_v<Visitor, const module_info&>, "visitor must be callable with const module_info&");

  std::shared_lock<std::shared_mutex> lock(index_mutex_);

  bool found = false;
  tree_.visit_overlapping(address, [&](const module_interval& interval) {
    visitor(interval.value);
    found = true;
    return false; // early termination after first match
  });

  return found;
}

template <typename Visitor>
bool module_range_index::try_rescan_and_visit(QBDI::rword address, module_scanner& scanner, Visitor&& visitor) {
  static_assert(std::is_invocable_v<Visitor, const module_info&>, "visitor must be callable with const module_info&");

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
    auto new_modules = scanner.scan_new_modules(known_bases);

    if (new_modules.empty()) {
      log_.dbg("no new modules discovered during rescan");
      return false;
    }

    // rebuild complete index with all current modules
    auto all_current_modules = scanner.scan_executable_modules();
    rebuild_from_modules(std::move(all_current_modules));

    log_.inf(
        "rescan completed successfully", redlog::field("new_modules", new_modules.size()),
        redlog::field("total_modules", size())
    );

    // try the lookup again with updated index
    return visit_containing(address, std::forward<Visitor>(visitor));

  } catch (const std::exception& e) {
    log_.err("exception during module rescan", redlog::field("error", e.what()));
    return false;
  }
}

template <typename Visitor> void module_range_index::visit_all(Visitor&& visitor) const {
  static_assert(std::is_invocable_v<Visitor, const module_info&>, "visitor must be callable with const module_info&");
  std::shared_lock<std::shared_mutex> lock(index_mutex_);
  tree_.visit_all([&](const module_interval& interval) { visitor(interval.value); });
}

} // namespace util
} // namespace w1