#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace w1::rewind {

struct memory_span {
  uint64_t base = 0;
  std::vector<uint8_t> bytes;
};

struct memory_read {
  std::vector<std::byte> bytes;
  std::vector<uint8_t> known;

  bool complete() const {
    if (known.empty()) {
      return true;
    }
    return std::all_of(known.begin(), known.end(), [](uint8_t value) { return value != 0; });
  }

  bool any_known() const {
    return std::any_of(known.begin(), known.end(), [](uint8_t value) { return value != 0; });
  }
};

class memory_store {
public:
  void clear();
  void apply_bytes(uint64_t address, std::span<const uint8_t> bytes);
  void apply_segments(std::span<const memory_span> segments);
  memory_read read(uint64_t address, size_t size) const;
  std::vector<memory_span> spans() const;

private:
  std::vector<memory_span> spans_;
};

} // namespace w1::rewind
