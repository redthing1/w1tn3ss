#include "memory_map.hpp"

#include "w1rewind/replay/mapping_state.hpp"
#include "w1rewind/replay/replay_context.hpp"

#include <algorithm>
#include <limits>

#include "w1replay/modules/path_resolver.hpp"

namespace w1replay::gdb {

namespace {

struct range {
  uint64_t start = 0;
  uint64_t end = 0;
};

gdbstub::mem_perm perms_from_mapping(w1::rewind::mapping_perm perms) {
  gdbstub::mem_perm out = gdbstub::mem_perm::none;
  if ((perms & w1::rewind::mapping_perm::read) != w1::rewind::mapping_perm::none) {
    out |= gdbstub::mem_perm::read;
  }
  if ((perms & w1::rewind::mapping_perm::write) != w1::rewind::mapping_perm::none) {
    out |= gdbstub::mem_perm::write;
  }
  if ((perms & w1::rewind::mapping_perm::exec) != w1::rewind::mapping_perm::none) {
    out |= gdbstub::mem_perm::exec;
  }
  return out;
}

uint64_t safe_end(uint64_t base, size_t size) {
  if (size == 0) {
    return base;
  }
  uint64_t end = base + static_cast<uint64_t>(size);
  if (end < base) {
    return std::numeric_limits<uint64_t>::max();
  }
  return end;
}

std::string resolve_mapping_name(
    const image_path_resolver* resolver, const w1::rewind::mapping_record& mapping,
    const w1::rewind::image_record* image
) {
  if (resolver && image) {
    if (auto resolved = resolver->resolve_image_path(*image)) {
      return *resolved;
    }
  }
  if (!mapping.name.empty()) {
    if (resolver) {
      if (auto resolved = resolver->resolve_region_name(mapping.name)) {
        return *resolved;
      }
    }
    return mapping.name;
  }
  if (image) {
    if (!image->name.empty()) {
      return image->name;
    }
    if (!image->identity.empty()) {
      return image->identity;
    }
  }
  return {};
}

std::vector<range> build_mapping_ranges_from_records(
    const std::vector<w1::rewind::mapping_record>& mappings, uint32_t space_id
) {
  std::vector<range> ranges;
  ranges.reserve(mappings.size());
  for (const auto& mapping : mappings) {
    if (mapping.space_id != space_id || mapping.size == 0) {
      continue;
    }
    range r{};
    r.start = mapping.base;
    r.end = mapping.base + mapping.size;
    ranges.push_back(r);
  }
  std::sort(ranges.begin(), ranges.end(), [](const range& a, const range& b) { return a.start < b.start; });
  return ranges;
}

std::vector<gdbstub::memory_region> build_recorded_regions(
    const w1::rewind::replay_state* state, const std::vector<range>& mapping_ranges
) {
  if (!state) {
    return {};
  }
  auto spans = state->memory_store().spans();
  if (spans.empty()) {
    return {};
  }

  std::vector<gdbstub::memory_region> regions;
  size_t range_index = 0;

  auto append_region = [&](uint64_t start, uint64_t end) {
    if (end <= start) {
      return;
    }
    gdbstub::memory_region region{};
    region.start = start;
    region.size = end - start;
    region.perms = gdbstub::mem_perm::read | gdbstub::mem_perm::write;
    region.name = "rewind.recorded";
    regions.push_back(std::move(region));
  };

  for (const auto& span : spans) {
    if (span.space_id != 0 || span.bytes.empty()) {
      continue;
    }
    uint64_t span_start = span.base;
    uint64_t span_end = safe_end(span.base, span.bytes.size());
    if (span_end <= span_start) {
      continue;
    }

    uint64_t cursor = span_start;
    while (range_index < mapping_ranges.size() && mapping_ranges[range_index].end <= cursor) {
      ++range_index;
    }

    size_t scan_index = range_index;
    while (scan_index < mapping_ranges.size() && mapping_ranges[scan_index].start < span_end) {
      const auto& range = mapping_ranges[scan_index];
      if (range.start > cursor) {
        append_region(cursor, std::min(range.start, span_end));
      }
      if (range.end >= span_end) {
        cursor = span_end;
        break;
      }
      cursor = std::max(cursor, range.end);
      ++scan_index;
    }

    if (cursor < span_end) {
      append_region(cursor, span_end);
    }

    range_index = scan_index;
  }

  return regions;
}

} // namespace

std::vector<gdbstub::memory_region> build_memory_map(
    const w1::rewind::replay_context& context, const w1::rewind::replay_state* state,
    const w1::rewind::mapping_state* mappings, const image_path_resolver* resolver
) {
  std::vector<gdbstub::memory_region> regions;
  regions.reserve(context.mappings.size());

  const uint32_t space_id = 0;
  static const std::vector<w1::rewind::mapping_range> k_empty_ranges;
  const bool use_mapping_state = mappings != nullptr;
  const auto* mapping_ranges = mappings ? [&]() -> const std::vector<w1::rewind::mapping_range>* {
    auto it = mappings->ranges_by_space().find(space_id);
    if (it == mappings->ranges_by_space().end()) {
      return &k_empty_ranges;
    }
    return &it->second;
  }()
      : nullptr;
  auto ranges_it = context.mapping_ranges_by_space.find(space_id);

  if (use_mapping_state) {
    for (const auto& range_entry : *mapping_ranges) {
      if (!range_entry.mapping || range_entry.end <= range_entry.start) {
        continue;
      }
      const auto& mapping = *range_entry.mapping;
      gdbstub::memory_region region{};
      region.start = range_entry.start;
      region.size = range_entry.end - range_entry.start;
      region.perms = perms_from_mapping(mapping.perms);
      region.name = resolve_mapping_name(resolver, mapping, context.find_image(mapping.image_id));
      regions.push_back(std::move(region));
    }
  } else if (ranges_it != context.mapping_ranges_by_space.end() && !ranges_it->second.empty()) {
    for (const auto& range_entry : ranges_it->second) {
      if (!range_entry.mapping || range_entry.end <= range_entry.start) {
        continue;
      }
      const auto& mapping = *range_entry.mapping;
      gdbstub::memory_region region{};
      region.start = range_entry.start;
      region.size = range_entry.end - range_entry.start;
      region.perms = perms_from_mapping(mapping.perms);
      region.name = resolve_mapping_name(resolver, mapping, context.find_image(mapping.image_id));
      regions.push_back(std::move(region));
    }
  }

  if (!use_mapping_state && (ranges_it == context.mapping_ranges_by_space.end() || ranges_it->second.empty())) {
    for (const auto& mapping : context.mappings) {
      if (mapping.space_id != space_id || mapping.size == 0) {
        continue;
      }
      gdbstub::memory_region region{};
      region.start = mapping.base;
      region.size = mapping.size;
      region.perms = perms_from_mapping(mapping.perms);
      region.name = resolve_mapping_name(resolver, mapping, context.find_image(mapping.image_id));
      regions.push_back(std::move(region));
    }
  }

  std::vector<range> ranges;
  if (use_mapping_state) {
    ranges.reserve(mapping_ranges->size());
    for (const auto& range_entry : *mapping_ranges) {
      if (range_entry.end <= range_entry.start) {
        continue;
      }
      ranges.push_back({range_entry.start, range_entry.end});
    }
  } else if (ranges_it != context.mapping_ranges_by_space.end() && !ranges_it->second.empty()) {
    ranges.reserve(ranges_it->second.size());
    for (const auto& range_entry : ranges_it->second) {
      if (range_entry.end <= range_entry.start) {
        continue;
      }
      ranges.push_back({range_entry.start, range_entry.end});
    }
  } else if (!use_mapping_state) {
    ranges = build_mapping_ranges_from_records(context.mappings, space_id);
  }
  auto recorded = build_recorded_regions(state, ranges);
  if (!recorded.empty()) {
    regions.insert(regions.end(), recorded.begin(), recorded.end());
  }

  return regions;
}

} // namespace w1replay::gdb
