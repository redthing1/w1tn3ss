#pragma once

#include <cstddef>

#include "w1base/arch_spec.hpp"

namespace w1::h00k::memory {

struct exec_block {
  void* address = nullptr;
  size_t size = 0;

  bool ok() const { return address != nullptr && size > 0; }
};

size_t page_size();
exec_block allocate_executable(size_t size);
exec_block allocate_near(void* target, size_t size, size_t range);
void free_executable(exec_block block);

inline exec_block allocate_trampoline(void* target, size_t size, const w1::arch::arch_spec& arch) {
  if (arch.arch_mode == w1::arch::mode::x86_64) {
    constexpr size_t kNearRange = 0x7FFFFFFF; // 2GB - 1 for RIP-relative reach
    auto block = allocate_near(target, size, kNearRange);
    if (block.ok()) {
      return block;
    }
  }
  return allocate_executable(size);
}

} // namespace w1::h00k::memory
