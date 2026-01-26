#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

#include "w1base/types.hpp"

namespace w1::util {

constexpr bool range_is_valid(uint64_t start, uint64_t end) { return start < end; }

constexpr uint64_t range_size(uint64_t start, uint64_t end) { return end > start ? end - start : 0; }

constexpr bool range_contains(uint64_t start, uint64_t end, uint64_t address) {
  return address >= start && address < end;
}

constexpr bool range_overlaps(uint64_t start, uint64_t end, uint64_t other_start, uint64_t other_end) {
  return start < other_end && other_start < end;
}

constexpr bool range_contains(const address_range& range, uint64_t address) {
  return range_contains(range.start, range.end, address);
}

constexpr bool range_overlaps(const address_range& left, const address_range& right) {
  return range_overlaps(left.start, left.end, right.start, right.end);
}

constexpr uint64_t range_size(const address_range& range) { return range_size(range.start, range.end); }

constexpr bool range_is_valid(const address_range& range) { return range_is_valid(range.start, range.end); }

inline bool compute_end(uint64_t start, size_t size, uint64_t* end) {
  if (!end) {
    return false;
  }

  if (size == 0) {
    *end = start;
    return true;
  }

  uint64_t end_value = start + static_cast<uint64_t>(size);
  if (end_value < start) {
    return false;
  }

  *end = end_value;
  return true;
}

inline uint64_t range_end_saturating(uint64_t start, size_t size) {
  uint64_t end = start + static_cast<uint64_t>(size);
  if (end < start) {
    return std::numeric_limits<uint64_t>::max();
  }
  return end;
}

inline void merge_ranges(std::vector<address_range>& ranges) {
  if (ranges.empty()) {
    return;
  }

  std::sort(ranges.begin(), ranges.end(), [](const auto& left, const auto& right) { return left.start < right.start; });

  std::vector<address_range> merged;
  merged.reserve(ranges.size());
  address_range current = ranges.front();

  for (size_t i = 1; i < ranges.size(); ++i) {
    const auto& next = ranges[i];
    if (next.start > current.end) {
      merged.push_back(current);
      current = next;
      continue;
    }
    current.end = std::max(current.end, next.end);
  }

  merged.push_back(current);
  ranges.swap(merged);
}

} // namespace w1::util
