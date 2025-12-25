#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <vector>

namespace p1ll::test_helpers {

inline std::vector<uint8_t> make_buffer(size_t size, uint8_t fill = 0x90) {
  return std::vector<uint8_t>(size, fill);
}

inline void write_bytes(std::vector<uint8_t>& buffer, size_t offset, std::initializer_list<uint8_t> bytes) {
  if (offset >= buffer.size()) {
    return;
  }
  size_t count = std::min(buffer.size() - offset, bytes.size());
  std::copy(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(count), buffer.begin() + offset);
}

} // namespace p1ll::test_helpers
