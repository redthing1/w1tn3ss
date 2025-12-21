#pragma once

#include <cstdint>
#include <cstddef>

#include "w1tn3ss/tracer/types.hpp"

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

} // namespace w1::util
