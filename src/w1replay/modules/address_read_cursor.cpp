#include "address_read_cursor.hpp"

#include <algorithm>
#include <limits>

#include "w1rewind/replay/mapping_state.hpp"
#include "w1rewind/replay/replay_context.hpp"

namespace w1replay {

image_read_result read_address_bytes_with_sources(
    const w1::rewind::replay_context& context,
    const w1::rewind::mapping_state* mapping_state,
    const image_address_index& index,
    uint64_t address,
    size_t size,
    uint32_t space_id,
    const address_read_sources& sources
) {
  image_read_result result = make_empty_image_read(size);
  if (size == 0) {
    result.error = "empty read";
    return result;
  }

  std::string last_error;
  auto merge_source = [&](const image_read_result& source, size_t dest_offset) {
    if (!source.error.empty()) {
      last_error = source.error;
    }
    merge_image_bytes_at(result, source, dest_offset);
  };

  uint64_t cursor = address;
  size_t remaining = size;
  size_t dest_offset = 0;

  while (remaining > 0) {
    auto match = index.find(cursor, 1, space_id);

    if (!match.has_value() || !match->mapping) {
      const auto* next =
          mapping_state ? mapping_state->find_mapping_after(space_id, cursor)
                        : context.find_mapping_after(space_id, cursor);
      if (!next || next->start <= cursor) {
        break;
      }
      uint64_t gap = next->start - cursor;
      if (gap > remaining) {
        break;
      }
      cursor += gap;
      dest_offset += static_cast<size_t>(gap);
      remaining -= static_cast<size_t>(gap);
      continue;
    }

    const auto* mapping = match->mapping;
    uint64_t mapping_end = match->range_end;
    if (mapping_end == 0) {
      mapping_end = mapping->base + mapping->size;
      if (mapping_end < mapping->base) {
        mapping_end = std::numeric_limits<uint64_t>::max();
      }
    }
    uint64_t max_len64 = mapping_end > cursor ? mapping_end - cursor : 0;
    if (max_len64 == 0) {
      break;
    }
    size_t chunk = static_cast<size_t>(std::min<uint64_t>(remaining, max_len64));

    if (match->image && sources.blob_index && sources.read_blob) {
      std::string blob_error;
      if (const auto* blob_index = sources.blob_index(*match->image, blob_error)) {
        merge_source(sources.read_blob(*blob_index, match->image_offset, chunk), dest_offset);
      } else if (!blob_error.empty()) {
        last_error = blob_error;
      }
    }

    if (sources.read_address) {
      merge_source(sources.read_address(space_id, cursor, chunk), dest_offset);
    }

    if (match->image && sources.read_image) {
      std::string image_error;
      image_read_result image_result = sources.read_image(*match->image, match->image_offset, chunk, image_error);
      if (!image_error.empty()) {
        last_error = image_error;
      }
      merge_source(image_result, dest_offset);
    }

    cursor += chunk;
    dest_offset += chunk;
    remaining -= chunk;

    if (result.complete) {
      break;
    }
  }

  if (!any_known(result)) {
    result.error = last_error.empty() ? "image bytes unavailable" : last_error;
  }

  return result;
}

} // namespace w1replay
