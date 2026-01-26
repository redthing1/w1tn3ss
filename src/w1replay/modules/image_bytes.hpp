#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace w1replay {

struct image_range {
  uint64_t va_start = 0;
  uint64_t mem_size = 0;
  uint64_t file_offset = 0;
  uint64_t file_size = 0;
  std::span<const std::byte> file_bytes{};
};

class image_file_reader {
public:
  virtual ~image_file_reader() = default;
  virtual bool read(uint64_t offset, std::span<std::byte> out, std::string& error) = 0;
};

struct image_layout {
  uint64_t link_base = 0;
  std::vector<image_range> ranges;
  std::shared_ptr<image_file_reader> file_reader;
};

struct image_read_result {
  std::vector<std::byte> bytes;
  std::vector<uint8_t> known;
  std::string error;
  bool complete = false;
};

image_read_result make_empty_image_read(size_t size);
bool any_known(const image_read_result& result);
bool all_known(const image_read_result& result);
void merge_image_bytes(image_read_result& dest, const image_read_result& src);
void merge_image_bytes_at(image_read_result& dest, const image_read_result& src, size_t dest_offset);

image_read_result read_image_bytes(const image_layout& layout, uint64_t image_offset, size_t size);

} // namespace w1replay
