#include "module_range_index.hpp"
#include <algorithm>
#include <iterator>

namespace w1 {
namespace util {

module_range_index::module_range_index(std::vector<module_info> modules) { rebuild_internal(std::move(modules)); }

const module_info* module_range_index::find_containing(QBDI::rword address) const noexcept {
  std::shared_lock<std::shared_mutex> lock(index_mutex_);

  const module_info* result = nullptr;
  tree_.visit_overlapping(address, [&](const module_interval& interval) {
    result = &interval.value;
    return false; // early termination
  });

  return result;
}

const module_info* module_range_index::find_by_name(const std::string& name) const noexcept {
  std::shared_lock<std::shared_mutex> lock(index_mutex_);

  auto it = name_index_.find(name);
  return (it != name_index_.end()) ? it->second : nullptr;
}

bool module_range_index::empty() const noexcept {
  std::shared_lock<std::shared_mutex> lock(index_mutex_);
  return tree_.empty();
}

size_t module_range_index::size() const noexcept {
  std::shared_lock<std::shared_mutex> lock(index_mutex_);
  return tree_.size();
}

void module_range_index::rebuild_from_modules(std::vector<module_info> modules) {
  std::unique_lock<std::shared_mutex> lock(index_mutex_);
  rebuild_internal(std::move(modules));
}

std::unordered_set<QBDI::rword> module_range_index::get_known_module_bases() const {
  std::shared_lock<std::shared_mutex> lock(index_mutex_);

  std::unordered_set<QBDI::rword> known_bases;
  known_bases.reserve(tree_.size());

  tree_.visit_all([&](const module_interval& interval) { known_bases.insert(interval.value.base_address); });

  return known_bases;
}

void module_range_index::build_name_index() {
  name_index_.clear();
  name_index_.reserve(tree_.size());

  tree_.visit_all([&](const module_interval& interval) {
    const module_info& mod = interval.value;
    if (!mod.name.empty()) {
      name_index_[mod.name] = &mod;
    }
  });
}

void module_range_index::rebuild_internal(std::vector<module_info> modules) {
  if (modules.empty()) {
    tree_ = interval_tree::interval_tree<QBDI::rword, module_info>();
    name_index_.clear();
    return;
  }

  // build intervals for tree construction
  std::vector<module_interval> intervals;
  intervals.reserve(modules.size());

  for (auto& mod : modules) {
    intervals.emplace_back(mod.base_address, mod.base_address + mod.size, std::move(mod));
  }

  // construct tree with move semantics
  tree_ = interval_tree::interval_tree<QBDI::rword, module_info>(
      std::make_move_iterator(intervals.begin()), std::make_move_iterator(intervals.end())
  );

  // build name index for fast name lookups
  build_name_index();
}

// template implementations are in the header file for proper linkage

} // namespace util
} // namespace w1