#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

#include "image_bytes.hpp"

namespace w1::rewind {
struct image_record;
struct replay_context;
} // namespace w1::rewind

namespace w1replay {

using image_address_reader = std::function<image_read_result(uint32_t space_id, uint64_t address, size_t size)>;

class image_reader {
public:
  virtual ~image_reader() = default;

  virtual image_read_result read_image_bytes(const w1::rewind::image_record& image, uint64_t offset, size_t size) = 0;
  virtual image_read_result read_address_bytes(
      const w1::rewind::replay_context& context, uint64_t address, size_t size, uint32_t space_id = 0
  ) = 0;
  virtual const image_layout* layout_for_image(const w1::rewind::image_record& image, std::string& error) = 0;
};

} // namespace w1replay
