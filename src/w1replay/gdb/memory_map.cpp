#include "memory_map.hpp"

#include <algorithm>

#include "w1rewind/format/trace_format.hpp"

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

bool address_in_ranges(uint64_t address, const std::vector<range>& ranges) {
  auto it = std::upper_bound(ranges.begin(), ranges.end(), address, [](uint64_t addr, const range& r) {
    return addr < r.start;
  });
  if (it == ranges.begin()) {
    return false;
  }
  --it;
  return address >= it->start && address < it->end;
}

std::vector<gdbstub::memory_region> build_recorded_regions(
    const w1::rewind::replay_state* state, const std::vector<range>& module_ranges
) {
  if (!state) {
    return {};
  }
  const auto& memory = state->memory_map();
  if (memory.empty()) {
    return {};
  }

  std::vector<uint64_t> addresses;
  addresses.reserve(memory.size());
  for (const auto& entry : memory) {
    if (!address_in_ranges(entry.first, module_ranges)) {
      addresses.push_back(entry.first);
    }
  }

  if (addresses.empty()) {
    return {};
  }

  std::sort(addresses.begin(), addresses.end());

  std::vector<gdbstub::memory_region> regions;
  uint64_t start = addresses.front();
  uint64_t prev = start;

  auto flush_range = [&](uint64_t range_start, uint64_t range_end) {
    gdbstub::memory_region region{};
    region.start = range_start;
    region.size = range_end - range_start + 1;
    region.perms = gdbstub::mem_perm::read | gdbstub::mem_perm::write;
    region.name = "rewind.recorded";
    regions.push_back(std::move(region));
  };

  for (size_t i = 1; i < addresses.size(); ++i) {
    uint64_t addr = addresses[i];
    if (addr == prev + 1) {
      prev = addr;
      continue;
    }
    flush_range(start, prev);
    start = addr;
    prev = addr;
  }
  flush_range(start, prev);

  return regions;
}

} // namespace

std::vector<gdbstub::memory_region> build_memory_map(
    const std::vector<w1::rewind::module_record>& modules,
    const std::vector<w1::rewind::memory_region_record>& memory_map, const w1::rewind::replay_state* state
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
      region.name = region_info.name;
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
        region.name = module.path;
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
