#include "w1h00k/memory/memory.hpp"

#include <cstdint>

#include <sys/mman.h>
#include <unistd.h>

namespace w1::h00k::memory {
namespace {

size_t align_up(size_t value, size_t alignment) {
  if (alignment == 0) {
    return value;
  }
  const size_t mask = alignment - 1;
  return (value + mask) & ~mask;
}

uintptr_t align_down(uintptr_t value, size_t alignment) {
  if (alignment == 0) {
    return value;
  }
  const uintptr_t mask = static_cast<uintptr_t>(alignment - 1);
  return value & ~mask;
}

} // namespace

size_t page_size() {
  long size = sysconf(_SC_PAGESIZE);
  if (size <= 0) {
    return 4096;
  }
  return static_cast<size_t>(size);
}

exec_block allocate_executable(size_t size) {
  if (size == 0) {
    return {};
  }

  const size_t page = page_size();
  const size_t aligned = align_up(size, page);

  int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
  int flags = MAP_PRIVATE | MAP_ANON;
#if defined(__APPLE__) && defined(MAP_JIT)
  flags |= MAP_JIT;
#endif

  void* addr = mmap(nullptr, aligned, prot, flags, -1, 0);
  if (addr == MAP_FAILED) {
    return {};
  }
  return {addr, aligned};
}

exec_block allocate_near(void* target, size_t size, size_t range) {
  if (!target || size == 0 || range == 0) {
    return {};
  }

  const size_t page = page_size();
  const size_t aligned = align_up(size, page);

  uintptr_t origin = reinterpret_cast<uintptr_t>(target);
  uintptr_t min_addr = origin > range ? origin - range : 0;
  uintptr_t max_addr = origin + range;
  if (max_addr < origin) {
    max_addr = UINTPTR_MAX;
  }
  if (max_addr < min_addr + aligned) {
    return {};
  }
  uintptr_t max_start = max_addr >= aligned ? max_addr - aligned : 0;
  min_addr = align_down(min_addr, page);
  max_start = align_down(max_start, page);

  int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
  int flags = MAP_PRIVATE | MAP_ANON;
#if defined(__APPLE__) && defined(MAP_JIT)
  flags |= MAP_JIT;
#endif

  auto try_map = [&](uintptr_t hint) -> void* {
#if defined(MAP_FIXED_NOREPLACE)
    void* addr = mmap(reinterpret_cast<void*>(hint), aligned, prot, flags | MAP_FIXED_NOREPLACE, -1, 0);
    if (addr == MAP_FAILED) {
      return nullptr;
    }
    return addr;
#else
    void* addr = mmap(reinterpret_cast<void*>(hint), aligned, prot, flags, -1, 0);
    if (addr == MAP_FAILED) {
      return nullptr;
    }
    uintptr_t addr_value = reinterpret_cast<uintptr_t>(addr);
    if (addr_value < min_addr || addr_value > max_start) {
      munmap(addr, aligned);
      return nullptr;
    }
    return addr;
#endif
  };

  constexpr size_t kMaxAttempts = 4096;
  size_t step = range / kMaxAttempts;
  if (step < page) {
    step = page;
  }
  step = align_up(step, page);

  for (size_t offset = 0; offset <= range; offset += step) {
    uintptr_t high = origin + offset;
    if (high <= max_start) {
      if (void* addr = try_map(high)) {
        return {addr, aligned};
      }
    }
    if (offset == 0) {
      continue;
    }
    if (origin >= offset) {
      uintptr_t low = origin - offset;
      if (low >= min_addr && low <= max_start) {
        if (void* addr = try_map(low)) {
          return {addr, aligned};
        }
      }
    }
  }

  return {};
}

void free_executable(exec_block block) {
  if (!block.address || block.size == 0) {
    return;
  }
  munmap(block.address, block.size);
}

} // namespace w1::h00k::memory
