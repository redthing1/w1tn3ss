#include "memory_range_index.hpp"
#include <QBDI/Memory.h>
#include <redlog.hpp>

namespace w1::util {

bool memory_range_index::check_access(QBDI::rword address, size_t size, access_type type) const {
  // Fast path: check against cached mappings
  {
    std::shared_lock lock(mutex_);
    if (initialized_ && check_access_internal(address, size, type)) {
      return true;
    }
  }

  // Slow path: refresh and try again (with rate limiting)
  auto now = std::chrono::steady_clock::now();
  if (now - last_refresh_ > min_refresh_interval) {
    refresh_internal();
  }

  std::shared_lock lock(mutex_);
  return check_access_internal(address, size, type);
}

bool memory_range_index::check_access_internal(QBDI::rword address, size_t size, uint32_t perms) const {
  if (size == 0) {
    return true;
  }

  QBDI::rword end = address + size - 1;

  // Check for overflow
  if (end < address) {
    return false;
  }

  // Check if entire range is covered by regions with required permissions
  QBDI::rword current = address;

  while (current <= end) {
    bool found = false;
    QBDI::rword next_check = current;

    tree_.visit_overlapping(current, [&](const memory_interval& interval) {
      if ((interval.value.permissions & perms) == perms) {
        found = true;
        // Move current to end of this region
        next_check = interval.value.end;
        return false; // Stop searching
      }
      return true; // Continue searching
    });

    if (!found) {
      return false;
    }

    // Move to next unchecked byte
    if (next_check >= end) {
      break;
    }
    current = next_check + 1;
  }

  return true;
}

const memory_region* memory_range_index::find_region(QBDI::rword address) const {
  std::shared_lock lock(mutex_);

  if (!initialized_) {
    lock.unlock();
    refresh_internal();
    lock.lock();
  }

  const memory_region* result = nullptr;
  tree_.visit_overlapping(address, [&](const memory_interval& interval) {
    result = &interval.value;
    return false; // Stop on first match
  });

  return result;
}

void memory_range_index::refresh() { refresh_internal(); }

bool memory_range_index::empty() const {
  std::shared_lock lock(mutex_);
  return tree_.empty();
}

void memory_range_index::refresh_internal() const {

  size_t map_count = 0;
  QBDI::qbdi_MemoryMap* maps = QBDI::qbdi_getCurrentProcessMaps(true, &map_count);

  if (!maps) {
    log_.err("failed to get process memory maps");
    return;
  }

  std::vector<memory_interval> intervals;
  intervals.reserve(map_count);

  for (size_t i = 0; i < map_count; ++i) {
    memory_region region{
        maps[i].start, maps[i].end, static_cast<uint32_t>(maps[i].permission), maps[i].name ? maps[i].name : ""
    };

    intervals.emplace_back(region.start, region.end, std::move(region));
  }

  QBDI::qbdi_freeMemoryMapArray(maps, map_count);

  // Build new tree (need write lock)
  std::unique_lock lock(mutex_);
  tree_ = interval_tree::interval_tree<QBDI::rword, memory_region>(
      std::make_move_iterator(intervals.begin()), std::make_move_iterator(intervals.end())
  );
  initialized_ = true;
  last_refresh_ = std::chrono::steady_clock::now();

  log_.dbg("refreshed memory maps", redlog::field("regions", map_count));
}

} // namespace w1::util