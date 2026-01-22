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
  (void)target;
  (void)range;
  return allocate_executable(size);
}

void free_executable(exec_block block) {
  if (!block.address || block.size == 0) {
    return;
  }
  munmap(block.address, block.size);
}

} // namespace w1::h00k::memory
