#include "memory_map_utils.hpp"

namespace w1::rewind {

namespace {
bool range_contains(uint64_t base, uint64_t size, uint64_t address) {
  if (size == 0) {
    return false;
  }
  uint64_t end = base + size;
  if (end < base) {
    return false;
  }
  return address >= base && address < end;
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
    for (const auto& module : modules) {
      if (!range_contains(module.base, module.size, region.base)) {
        continue;
      }
      region.image_id = module.id;
      break;
    }
  }
}

} // namespace w1::rewind
