#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "w1rewind/format/trace_format.hpp"

namespace w1::rewind {

struct image_blob_span {
  uint64_t offset = 0;
  uint64_t end = 0;
  const uint8_t* data = nullptr;
  size_t size = 0;
};

struct image_blob_index {
  std::vector<image_blob_span> spans;
};

bool build_image_blob_index(std::span<const image_blob_record> blobs, image_blob_index& out, std::string& error);

} // namespace w1::rewind
