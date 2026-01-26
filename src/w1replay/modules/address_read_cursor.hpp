#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

#include "address_index.hpp"
#include "image_bytes.hpp"
#include "image_reader.hpp"

namespace w1::rewind {
struct image_blob_index;
struct image_record;
struct replay_context;
class mapping_state;
} // namespace w1::rewind

namespace w1replay {

struct address_read_sources {
  std::function<const w1::rewind::image_blob_index*(const w1::rewind::image_record&, std::string&)> blob_index;
  std::function<image_read_result(const w1::rewind::image_blob_index&, uint64_t, size_t)> read_blob;
  image_address_reader read_address;
  std::function<image_read_result(const w1::rewind::image_record&, uint64_t, size_t, std::string&)> read_image;
};

image_read_result read_address_bytes_with_sources(
    const w1::rewind::replay_context& context, const w1::rewind::mapping_state* mapping_state,
    const image_address_index& index, uint64_t address, size_t size, uint32_t space_id,
    const address_read_sources& sources
);

} // namespace w1replay
