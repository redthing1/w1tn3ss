#include "module_range_index.hpp"
#include <algorithm>
#include <iterator>

namespace w1 {
namespace util {

module_range_index::module_range_index(std::vector<module_info> modules) {
  if (modules.empty()) {
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

const module_info* module_range_index::find_containing(QBDI::rword address) const noexcept {
  const module_info* result = nullptr;

  tree_.visit_overlapping(address, [&](const module_interval& interval) {
    result = &interval.value;
    return false; // early termination
  });

  return result;
}

const module_info* module_range_index::find_by_name(const std::string& name) const noexcept {
  auto it = name_index_.find(name);
  return (it != name_index_.end()) ? it->second : nullptr;
}

bool module_range_index::empty() const noexcept { return tree_.empty(); }

size_t module_range_index::size() const noexcept { return tree_.size(); }

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

} // namespace util
} // namespace w1