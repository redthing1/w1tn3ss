#pragma once

#include "module_info.hpp"
#include "interval_tree.hpp"
#include <vector>
#include <unordered_map>
#include <type_traits>
#include <QBDI.h>

namespace w1 {
namespace util {

/**
 * @brief fast address-to-module lookup using interval tree
 * @details immutable after construction, thread-safe for concurrent reads.
 * optimized for point queries with o(log n + k) complexity where k is typically 1.
 */
class module_range_index {
public:
  /**
   * @brief construct index from vector of modules
   * @param modules vector of module_info objects to index
   * @details sorts modules and builds interval tree. construction is o(n log n).
   */
  explicit module_range_index(std::vector<module_info> modules);

  /**
   * @brief find module containing the given address
   * @param address memory address to query
   * @return pointer to module_info if found, nullptr otherwise
   * @note this method is noexcept and thread-safe, no logging
   */
  const module_info* find_containing(QBDI::rword address) const noexcept;

  /**
   * @brief visit module containing the given address using visitor pattern
   * @param address memory address to query
   * @param visitor callable invoked with const module_info& if found
   * @return true if module found and visitor called, false otherwise
   * @note zero-allocation hot path optimization, no logging
   */
  template <typename Visitor> bool visit_containing(QBDI::rword address, Visitor&& visitor) const;

  /**
   * @brief visit all modules in the index
   * @param visitor callable invoked with interval for each module
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

  // optional name-based lookup cache
  std::unordered_map<std::string, const module_info*> name_index_;

  void build_name_index();
};

template <typename Visitor> bool module_range_index::visit_containing(QBDI::rword address, Visitor&& visitor) const {
  static_assert(std::is_invocable_v<Visitor, const module_info&>, "visitor must be callable with const module_info&");

  bool found = false;
  tree_.visit_overlapping(address, [&](const module_interval& interval) {
    visitor(interval.value);
    found = true;
    return false; // early termination after first match
  });

  return found;
}

template <typename Visitor> void module_range_index::visit_all(Visitor&& visitor) const {
  tree_.visit_all(std::forward<Visitor>(visitor));
}

} // namespace util
} // namespace w1