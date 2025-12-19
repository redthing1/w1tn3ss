#pragma once

#include <cstddef>
#include <cstdint>

namespace p1ll::utils {

inline uint64_t align_down(uint64_t value, size_t alignment) {
  if (alignment == 0) {
    return value;
  }
  uint64_t mask = static_cast<uint64_t>(alignment - 1);
  return value & ~mask;
}

inline uint64_t align_up(uint64_t value, size_t alignment) {
  if (alignment == 0) {
    return value;
  }
  uint64_t mask = static_cast<uint64_t>(alignment - 1);
  return (value + mask) & ~mask;
}

} // namespace p1ll::utils
