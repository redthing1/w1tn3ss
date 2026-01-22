#include "w1h00k/memory/memory.hpp"

#include <algorithm>
#include <cstdint>

#include <windows.h>

namespace w1::h00k::memory {
namespace {

size_t align_up(size_t value, size_t alignment) {
  if (alignment == 0) {
    return value;
  }
  const size_t mask = alignment - 1;
  return (value + mask) & ~mask;
}

uintptr_t align_up_ptr(uintptr_t value, size_t alignment) {
  if (alignment == 0) {
    return value;
  }
  const uintptr_t mask = static_cast<uintptr_t>(alignment - 1);
  return (value + mask) & ~mask;
}

uintptr_t align_down_ptr(uintptr_t value, size_t alignment) {
  if (alignment == 0) {
    return value;
  }
  const uintptr_t mask = static_cast<uintptr_t>(alignment - 1);
  return value & ~mask;
}

} // namespace

size_t page_size() {
  SYSTEM_INFO info{};
  GetSystemInfo(&info);
  return static_cast<size_t>(info.dwPageSize);
}

exec_block allocate_executable(size_t size) {
  if (size == 0) {
    return {};
  }

  const size_t page = page_size();
  const size_t aligned = align_up(size, page);

  void* addr = VirtualAlloc(nullptr, aligned, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!addr) {
    return {};
  }
  return {addr, aligned};
}

exec_block allocate_near(void* target, size_t size, size_t range) {
  if (!target || size == 0 || range == 0) {
    return {};
  }

  SYSTEM_INFO info{};
  GetSystemInfo(&info);
  const size_t page = static_cast<size_t>(info.dwPageSize);
  const size_t granularity = static_cast<size_t>(info.dwAllocationGranularity);
  const size_t aligned = align_up(size, page);

  uintptr_t origin = reinterpret_cast<uintptr_t>(target);
  uintptr_t min_addr = origin > range ? origin - range : 0;
  uintptr_t max_addr = origin + range;
  if (max_addr < origin) {
    max_addr = UINTPTR_MAX;
  }

  const uintptr_t min_app = reinterpret_cast<uintptr_t>(info.lpMinimumApplicationAddress);
  const uintptr_t max_app = reinterpret_cast<uintptr_t>(info.lpMaximumApplicationAddress);
  min_addr = std::max(min_addr, min_app);
  max_addr = std::min(max_addr, max_app);

  if (max_addr < min_addr + aligned) {
    return {};
  }
  uintptr_t max_start = max_addr >= aligned ? max_addr - aligned : 0;
  min_addr = align_down_ptr(min_addr, granularity);
  max_start = align_down_ptr(max_start, granularity);

  auto region_fits = [&](uintptr_t addr, size_t request) -> bool {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<void*>(addr), &mbi, sizeof(mbi)) != sizeof(mbi)) {
      return false;
    }
    if (mbi.State != MEM_FREE) {
      return false;
    }
    uintptr_t region_base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    uintptr_t region_end = region_base + mbi.RegionSize;
    if (region_end < region_base) {
      return false;
    }
    if (addr < region_base) {
      return false;
    }
    size_t offset = static_cast<size_t>(addr - region_base);
    if (mbi.RegionSize < offset + request) {
      return false;
    }
    return true;
  };

  auto try_alloc = [&](uintptr_t addr) -> void* {
    if (addr < min_addr || addr > max_start) {
      return nullptr;
    }
    if (!region_fits(addr, aligned)) {
      return nullptr;
    }
    return VirtualAlloc(reinterpret_cast<void*>(addr), aligned, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  };

  uintptr_t origin_aligned = align_down_ptr(origin, granularity);

  bool found = false;
  uintptr_t best = 0;
  uintptr_t best_distance = UINTPTR_MAX;
  uintptr_t cursor = align_down_ptr(min_addr, granularity);
  while (cursor <= max_addr) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<void*>(cursor), &mbi, sizeof(mbi)) != sizeof(mbi)) {
      break;
    }
    uintptr_t region_base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    uintptr_t region_end = region_base + mbi.RegionSize;
    if (region_end < region_base) {
      break;
    }
    if (mbi.State == MEM_FREE) {
      uintptr_t region_start = std::max(region_base, min_addr);
      uintptr_t region_limit = std::min(region_end, max_addr + 1);
      if (region_limit > region_start && region_limit - region_start >= aligned) {
        uintptr_t candidate_min = align_up_ptr(region_start, granularity);
        uintptr_t candidate_max = align_down_ptr(region_limit - aligned, granularity);
        if (candidate_min <= candidate_max) {
          uintptr_t candidate = origin_aligned;
          if (candidate < candidate_min) {
            candidate = candidate_min;
          } else if (candidate > candidate_max) {
            candidate = candidate_max;
          }
          uintptr_t distance = candidate >= origin ? candidate - origin : origin - candidate;
          if (!found || distance < best_distance) {
            best = candidate;
            best_distance = distance;
            found = true;
            if (distance == 0) {
              break;
            }
          }
        }
      }
    }
    if (region_end <= cursor) {
      break;
    }
    cursor = region_end;
  }

  if (found) {
    if (void* addr = try_alloc(best)) {
      return {addr, aligned};
    }
  }

  for (cursor = align_down_ptr(min_addr, granularity); cursor <= max_addr;) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<void*>(cursor), &mbi, sizeof(mbi)) != sizeof(mbi)) {
      break;
    }
    uintptr_t region_base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    uintptr_t region_end = region_base + mbi.RegionSize;
    if (region_end < region_base) {
      break;
    }
    if (mbi.State == MEM_FREE) {
      uintptr_t region_start = std::max(region_base, min_addr);
      uintptr_t region_limit = std::min(region_end, max_addr + 1);
      if (region_limit > region_start && region_limit - region_start >= aligned) {
        uintptr_t candidate = align_up_ptr(region_start, granularity);
        if (candidate <= align_down_ptr(region_limit - aligned, granularity)) {
          if (void* addr = try_alloc(candidate)) {
            return {addr, aligned};
          }
        }
      }
    }
    if (region_end <= cursor) {
      break;
    }
    cursor = region_end;
  }

  return {};
}

void free_executable(exec_block block) {
  if (!block.address || block.size == 0) {
    return;
  }
  VirtualFree(block.address, 0, MEM_RELEASE);
}

} // namespace w1::h00k::memory
