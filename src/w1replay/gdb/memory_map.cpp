#include "memory_map.hpp"

#include <algorithm>
#include <limits>

#include "w1rewind/format/trace_format.hpp"

#include "w1replay/modules/path_resolver.hpp"

namespace w1replay::gdb {

namespace {

struct range {
  uint64_t start = 0;
  uint64_t end = 0;
};

gdbstub::mem_perm perms_from_module(w1::rewind::module_perm perms) {
  gdbstub::mem_perm out = gdbstub::mem_perm::none;
  if ((perms & w1::rewind::module_perm::read) != w1::rewind::module_perm::none) {
    out |= gdbstub::mem_perm::read;
  }
  if ((perms & w1::rewind::module_perm::write) != w1::rewind::module_perm::none) {
    out |= gdbstub::mem_perm::write;
  }
  if ((perms & w1::rewind::module_perm::exec) != w1::rewind::module_perm::none) {
    out |= gdbstub::mem_perm::exec;
  }
  return out;
}

std::string resolve_module_path(const module_path_resolver* resolver, const w1::rewind::module_record& module) {
  if (!resolver || module.path.empty()) {
    return module.path;
  }
  auto resolved = resolver->resolve_module_path(module);
  if (resolved.has_value()) {
    return *resolved;
  }
  return module.path;
}

std::string resolve_region_name(const module_path_resolver* resolver, const std::string& name) {
  if (!resolver || name.empty()) {
    return name;
  }
  auto resolved = resolver->resolve_region_name(name);
  if (resolved.has_value()) {
    return *resolved;
  }
  return name;
}

std::vector<range> build_module_ranges(const std::vector<w1::rewind::module_record>& modules) {
  std::vector<range> ranges;
  ranges.reserve(modules.size());
  for (const auto& module : modules) {
    range r{};
    r.start = module.base;
    r.end = module.base + module.size;
    ranges.push_back(r);
  }
  std::sort(ranges.begin(), ranges.end(), [](const range& a, const range& b) { return a.start < b.start; });
  return ranges;
}

std::vector<range> build_memory_ranges(const std::vector<w1::rewind::memory_region_record>& regions) {
  std::vector<range> ranges;
  ranges.reserve(regions.size());
  for (const auto& region : regions) {
    range r{};
    r.start = region.base;
    r.end = region.base + region.size;
    ranges.push_back(r);
  }
  std::sort(ranges.begin(), ranges.end(), [](const range& a, const range& b) { return a.start < b.start; });
  return ranges;
}

std::vector<gdbstub::memory_region> build_recorded_regions(
    const w1::rewind::replay_state* state, const std::vector<range>& module_ranges
) {
  if (!state) {
    return {};
  }
  auto spans = state->memory_store().spans();
  if (spans.empty()) {
    return {};
  }

  auto safe_end = [](uint64_t base, size_t size) {
    if (size == 0) {
      return base;
    }
    uint64_t end = base + static_cast<uint64_t>(size);
    if (end < base) {
      return std::numeric_limits<uint64_t>::max();
    }
    return end;
  };

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
    if (span.bytes.empty()) {
      continue;
    }
    uint64_t span_start = span.base;
    uint64_t span_end = safe_end(span.base, span.bytes.size());
    if (span_end <= span_start) {
      continue;
    }

    uint64_t cursor = span_start;
    while (range_index < module_ranges.size() && module_ranges[range_index].end <= cursor) {
      ++range_index;
    }

    size_t scan_index = range_index;
    while (scan_index < module_ranges.size() && module_ranges[scan_index].start < span_end) {
      const auto& range = module_ranges[scan_index];
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
    const std::vector<w1::rewind::module_record>& modules,
    const std::vector<w1::rewind::memory_region_record>& memory_map, const w1::rewind::replay_state* state,
    const module_path_resolver* resolver
) {
  std::vector<gdbstub::memory_region> regions;
  const bool use_memory_map = !memory_map.empty();
  if (use_memory_map) {
    regions.reserve(memory_map.size());
    for (const auto& region_info : memory_map) {
      gdbstub::memory_region region{};
      region.start = region_info.base;
      region.size = region_info.size;
      region.perms = perms_from_module(region_info.permissions);
      region.name = resolve_region_name(resolver, region_info.name);
      regions.push_back(std::move(region));
    }
  } else if (!modules.empty()) {
    regions.reserve(modules.size());
    for (const auto& module : modules) {
      gdbstub::memory_region region{};
      region.start = module.base;
      region.size = module.size;
      region.perms = perms_from_module(module.permissions);
      if (!module.path.empty()) {
        region.name = resolve_module_path(resolver, module);
      }
      regions.push_back(std::move(region));
    }
  }

  auto ranges = use_memory_map ? build_memory_ranges(memory_map) : build_module_ranges(modules);
  auto recorded = build_recorded_regions(state, ranges);
  if (!recorded.empty()) {
    regions.insert(regions.end(), recorded.begin(), recorded.end());
  }

  return regions;
}

} // namespace w1replay::gdb
