#include "w1h00k/memory/memory.hpp"

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
  (void)target;
  (void)range;
  return allocate_executable(size);
}

void free_executable(exec_block block) {
  if (!block.address || block.size == 0) {
    return;
  }
  VirtualFree(block.address, 0, MEM_RELEASE);
}

} // namespace w1::h00k::memory
