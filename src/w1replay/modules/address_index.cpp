#include "address_index.hpp"

#include <algorithm>
#include <limits>
#include <unordered_map>

namespace w1replay {

namespace {
uint64_t safe_end(uint64_t base, uint64_t size) {
  if (size == 0) {
    return base;
  }
  uint64_t end = base + size;
  if (end < base) {
    return std::numeric_limits<uint64_t>::max();
  }
  return end;
}

bool contains_range(uint64_t start, uint64_t end, uint64_t address, uint64_t range_end) {
  return address >= start && range_end <= end;
}
} // namespace

module_address_index::module_address_index(const w1::rewind::replay_context& context) {
  std::unordered_map<uint64_t, const w1::rewind::module_record*> modules_by_id;
  modules_by_id.reserve(context.modules.size());
  for (const auto& module : context.modules) {
    modules_by_id.emplace(module.id, &module);
    if (module.size == 0) {
      continue;
    }
    uint64_t end = safe_end(module.base, module.size);
    if (end <= module.base) {
      continue;
    }
    module_ranges_.push_back(address_range{module.base, end, &module});
  }

  if (!context.memory_map.empty()) {
    region_ranges_.reserve(context.memory_map.size());
    for (const auto& region : context.memory_map) {
      if (region.size == 0 || region.image_id == 0) {
        continue;
      }
      auto it = modules_by_id.find(region.image_id);
      if (it == modules_by_id.end()) {
        continue;
      }
      uint64_t end = safe_end(region.base, region.size);
      if (end <= region.base) {
        continue;
      }
      region_ranges_.push_back(address_range{region.base, end, it->second});
    }
  }

  auto by_start = [](const address_range& left, const address_range& right) { return left.start < right.start; };
  std::sort(region_ranges_.begin(), region_ranges_.end(), by_start);
  std::sort(module_ranges_.begin(), module_ranges_.end(), by_start);
}

std::optional<module_address_match> module_address_index::find(uint64_t address, uint64_t size) const {
  if (size == 0) {
    return std::nullopt;
  }
  uint64_t end = safe_end(address, size);
  if (end <= address) {
    return std::nullopt;
  }

  if (auto match = find_in_ranges(region_ranges_, address, end)) {
    return match;
  }
  return find_in_ranges(module_ranges_, address, end);
}

std::optional<module_address_match> module_address_index::find_in_ranges(
    const std::vector<address_range>& ranges, uint64_t address, uint64_t end
) const {
  for (const auto& range : ranges) {
    if (end <= range.start) {
      break;
    }
    if (!contains_range(range.start, range.end, address, end)) {
      continue;
    }
    const auto* module = range.module;
    if (!module || module->size == 0) {
      continue;
    }
    uint64_t module_end = safe_end(module->base, module->size);
    if (module_end <= module->base) {
      continue;
    }
    if (!contains_range(module->base, module_end, address, end)) {
      continue;
    }
    module_address_match match{};
    match.module = module;
    match.module_offset = address - module->base;
    return match;
  }
  return std::nullopt;
}

} // namespace w1replay
