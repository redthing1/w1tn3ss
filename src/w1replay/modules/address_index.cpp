#include "address_index.hpp"

#include <algorithm>
#include <limits>

#include "w1rewind/replay/mapping_state.hpp"

namespace w1replay {

namespace {

uint64_t safe_end(uint64_t base, uint64_t size) {
  if (size == 0) {
    return base;
  }
  uint64_t end = base + size;
  if (end < base) {
    return std::numeric_limits<uint64_t>::max();
  }
  return end;
}

const w1::rewind::mapping_range* find_range(
    const std::vector<w1::rewind::mapping_range>& ranges, uint64_t address
) {
  if (ranges.empty()) {
    return nullptr;
  }
  auto upper = std::upper_bound(ranges.begin(), ranges.end(), address,
                                [](uint64_t value, const w1::rewind::mapping_range& range) {
                                  return value < range.start;
                                });
  if (upper == ranges.begin()) {
    return nullptr;
  }
  --upper;
  if (address >= upper->end) {
    return nullptr;
  }
  return &*upper;
}

} // namespace

image_address_index::image_address_index(
    const w1::rewind::replay_context& context, const w1::rewind::mapping_state* mappings
)
    : context_(context), mappings_(mappings) {}

std::optional<image_address_match> image_address_index::find(
    uint64_t address, uint64_t size, uint32_t space_id
) const {
  if (size == 0) {
    return std::nullopt;
  }

  const w1::rewind::mapping_range* range = nullptr;
  if (mappings_) {
    auto it = mappings_->ranges_by_space().find(space_id);
    if (it != mappings_->ranges_by_space().end()) {
      range = find_range(it->second, address);
    }
  } else {
    auto it = context_.mapping_ranges_by_space.find(space_id);
    if (it != context_.mapping_ranges_by_space.end()) {
      range = find_range(it->second, address);
    }
  }

  if (!range || !range->mapping) {
    return std::nullopt;
  }

  const uint64_t end = safe_end(address, size);
  if (end <= address || end > range->end) {
    return std::nullopt;
  }

  const auto* mapping = range->mapping;
  if (address < mapping->base) {
    return std::nullopt;
  }
  uint64_t mapping_offset = address - mapping->base;

  image_address_match match{};
  match.mapping = mapping;
  match.image = context_.find_image(mapping->image_id);
  match.image_offset = mapping->image_offset + mapping_offset;
  match.range_start = range->start;
  match.range_end = range->end;
  return match;
}

} // namespace w1replay
