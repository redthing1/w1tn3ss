#include "mapping_state.hpp"

#include <algorithm>
#include <limits>

namespace w1::rewind {

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

bool add_overflows(uint64_t base, uint64_t addend) { return base > std::numeric_limits<uint64_t>::max() - addend; }

} // namespace

bool mapping_state::reset(std::span<const mapping_record> initial, std::string& error) {
  error.clear();
  storage_.clear();
  ranges_by_space_.clear();
  for (const auto& record : initial) {
    if (!apply_event(record, error)) {
      storage_.clear();
      ranges_by_space_.clear();
      if (error.empty()) {
        error = "invalid mapping record";
      }
      return false;
    }
  }
  return true;
}

bool mapping_state::apply_event(const mapping_record& record, std::string& error) {
  error.clear();
  switch (record.kind) {
  case mapping_event_kind::map:
    return apply_map(record, error);
  case mapping_event_kind::protect:
    return apply_protect(record, error);
  case mapping_event_kind::unmap:
    return apply_unmap(record, error);
  default:
    error = "unknown mapping event kind";
    return false;
  }
}

const mapping_record* mapping_state::find_mapping_for_address(
    uint32_t space_id, uint64_t address, uint64_t size, uint64_t& mapping_offset
) const {
  mapping_offset = 0;
  if (size == 0) {
    return nullptr;
  }

  auto it = ranges_by_space_.find(space_id);
  if (it == ranges_by_space_.end() || it->second.empty()) {
    return nullptr;
  }
  const auto& ranges = it->second;
  auto upper = std::upper_bound(ranges.begin(), ranges.end(), address, [](uint64_t value, const mapping_range& range) {
    return value < range.start;
  });
  if (upper == ranges.begin()) {
    return nullptr;
  }
  --upper;
  if (!upper->mapping || address >= upper->end) {
    return nullptr;
  }
  uint64_t address_end = safe_end(address, size);
  if (address_end <= address || address_end > upper->end) {
    return nullptr;
  }
  const auto* mapping = upper->mapping;
  if (address < mapping->base) {
    return nullptr;
  }
  mapping_offset = address - mapping->base;
  return mapping;
}

const mapping_range* mapping_state::find_mapping_after(uint32_t space_id, uint64_t address) const {
  auto it = ranges_by_space_.find(space_id);
  if (it == ranges_by_space_.end() || it->second.empty()) {
    return nullptr;
  }
  const auto& ranges = it->second;
  auto lower = std::lower_bound(ranges.begin(), ranges.end(), address, [](const mapping_range& range, uint64_t value) {
    return range.start < value;
  });
  if (lower == ranges.end()) {
    return nullptr;
  }
  return &*lower;
}

bool mapping_state::snapshot(std::vector<mapping_record>& out, std::string& error) const {
  error.clear();
  out.clear();
  for (const auto& [space_id, ranges] : ranges_by_space_) {
    for (const auto& range : ranges) {
      if (!range.mapping || range.end <= range.start) {
        continue;
      }
      mapping_record record = *range.mapping;
      record.kind = mapping_event_kind::map;
      record.space_id = space_id;
      record.base = range.start;
      record.size = range.end - range.start;

      if (record.base >= range.mapping->base) {
        uint64_t delta = record.base - range.mapping->base;
        if (add_overflows(record.image_offset, delta)) {
          error = "mapping image offset overflows";
          return false;
        }
        record.image_offset += delta;
      }

      out.push_back(std::move(record));
    }
  }
  std::sort(out.begin(), out.end(), [](const mapping_record& a, const mapping_record& b) {
    if (a.space_id != b.space_id) {
      return a.space_id < b.space_id;
    }
    if (a.base != b.base) {
      return a.base < b.base;
    }
    return a.size < b.size;
  });
  return true;
}

bool mapping_state::apply_map(const mapping_record& record, std::string& error) {
  if (record.size == 0) {
    return true;
  }
  uint64_t end = safe_end(record.base, record.size);
  if (end <= record.base) {
    error = "mapping range invalid";
    return false;
  }

  auto& ranges = ranges_by_space_[record.space_id];
  std::vector<mapping_range> updated;
  updated.reserve(ranges.size() + 1);

  for (const auto& range : ranges) {
    if (range.end <= record.base || range.start >= end) {
      updated.push_back(range);
      continue;
    }
    if (range.start < record.base) {
      mapping_range left = range;
      left.end = record.base;
      if (left.end > left.start) {
        updated.push_back(left);
      }
    }
    if (range.end > end) {
      mapping_range right = range;
      right.start = end;
      if (right.end > right.start) {
        updated.push_back(right);
      }
    }
  }

  storage_.push_back(record);
  mapping_range incoming{};
  incoming.start = record.base;
  incoming.end = end;
  incoming.mapping = &storage_.back();
  updated.push_back(incoming);

  std::sort(updated.begin(), updated.end(), [](const mapping_range& a, const mapping_range& b) {
    return a.start < b.start;
  });
  ranges.swap(updated);
  return true;
}

bool mapping_state::apply_unmap(const mapping_record& record, std::string& error) {
  if (record.size == 0) {
    return true;
  }
  uint64_t end = safe_end(record.base, record.size);
  if (end <= record.base) {
    error = "mapping range invalid";
    return false;
  }

  auto it = ranges_by_space_.find(record.space_id);
  if (it == ranges_by_space_.end() || it->second.empty()) {
    return true;
  }

  auto& ranges = it->second;
  std::vector<mapping_range> updated;
  updated.reserve(ranges.size());

  for (const auto& range : ranges) {
    if (range.end <= record.base || range.start >= end) {
      updated.push_back(range);
      continue;
    }
    if (range.start < record.base) {
      mapping_range left = range;
      left.end = record.base;
      if (left.end > left.start) {
        updated.push_back(left);
      }
    }
    if (range.end > end) {
      mapping_range right = range;
      right.start = end;
      if (right.end > right.start) {
        updated.push_back(right);
      }
    }
  }

  std::sort(updated.begin(), updated.end(), [](const mapping_range& a, const mapping_range& b) {
    return a.start < b.start;
  });
  ranges.swap(updated);
  return true;
}

bool mapping_state::apply_protect(const mapping_record& record, std::string& error) {
  if (record.size == 0) {
    return true;
  }
  uint64_t end = safe_end(record.base, record.size);
  if (end <= record.base) {
    error = "mapping range invalid";
    return false;
  }

  auto it = ranges_by_space_.find(record.space_id);
  if (it == ranges_by_space_.end() || it->second.empty()) {
    return true;
  }

  auto& ranges = it->second;
  std::vector<mapping_range> updated;
  updated.reserve(ranges.size() + 1);

  for (const auto& range : ranges) {
    if (range.end <= record.base || range.start >= end || !range.mapping) {
      updated.push_back(range);
      continue;
    }
    if (range.start < record.base) {
      mapping_range left = range;
      left.end = record.base;
      if (left.end > left.start) {
        updated.push_back(left);
      }
    }

    uint64_t overlap_start = std::max(range.start, record.base);
    uint64_t overlap_end = std::min(range.end, end);
    if (overlap_end > overlap_start) {
      mapping_record updated_record = *range.mapping;
      updated_record.kind = mapping_event_kind::map;
      updated_record.perms = record.perms;
      updated_record.flags = record.flags;
      storage_.push_back(std::move(updated_record));
      mapping_range mid{};
      mid.start = overlap_start;
      mid.end = overlap_end;
      mid.mapping = &storage_.back();
      updated.push_back(mid);
    }

    if (range.end > end) {
      mapping_range right = range;
      right.start = end;
      if (right.end > right.start) {
        updated.push_back(right);
      }
    }
  }

  std::sort(updated.begin(), updated.end(), [](const mapping_range& a, const mapping_range& b) {
    return a.start < b.start;
  });
  ranges.swap(updated);
  return true;
}

} // namespace w1::rewind
