#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace w1replay {

struct image_range {
  uint64_t va_start = 0;
  uint64_t mem_size = 0;
  std::span<const std::byte> file_bytes{};
};

struct image_layout {
  uint64_t link_base = 0;
  std::vector<image_range> ranges;
};

struct image_read_result {
  std::vector<std::byte> bytes;
  std::vector<uint8_t> known;
  std::string error;
  bool complete = false;
};

image_read_result read_image_bytes(const image_layout& layout, uint64_t module_offset, size_t size);

} // namespace w1replay
