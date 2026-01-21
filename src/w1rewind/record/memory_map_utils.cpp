#include "memory_map_utils.hpp"

#include <limits>

namespace w1::rewind {

namespace {
bool add_overflows(uint64_t base, uint64_t addend) { return base > std::numeric_limits<uint64_t>::max() - addend; }

uint64_t range_end(uint64_t base, uint64_t size) {
  if (size == 0) {
    return base;
  }
  if (add_overflows(base, size)) {
    return std::numeric_limits<uint64_t>::max();
  }
  return base + size;
}

uint64_t overlap_size(uint64_t base_a, uint64_t size_a, uint64_t base_b, uint64_t size_b) {
  if (size_a == 0 || size_b == 0) {
    return 0;
  }
  uint64_t end_a = range_end(base_a, size_a);
  uint64_t end_b = range_end(base_b, size_b);
  if (end_a <= base_b || end_b <= base_a) {
    return 0;
  }
  uint64_t start = std::max(base_a, base_b);
  uint64_t end = std::min(end_a, end_b);
  if (end <= start) {
    return 0;
  }
  return end - start;
}
} // namespace

void assign_memory_map_image_ids(
    std::vector<memory_region_record>& regions, const std::vector<module_record>& modules
) {
  if (regions.empty() || modules.empty()) {
    return;
  }

  for (auto& region : regions) {
    if (region.image_id != 0 || region.size == 0) {
      continue;
    }
    uint64_t best_overlap = 0;
    uint64_t best_id = 0;
    for (const auto& module : modules) {
      uint64_t overlap = overlap_size(region.base, region.size, module.base, module.size);
      if (overlap == 0) {
        continue;
      }
      if (overlap > best_overlap) {
        best_overlap = overlap;
        best_id = module.id;
      }
    }
    if (best_id != 0) {
      region.image_id = best_id;
    }
  }
}

} // namespace w1::rewind
