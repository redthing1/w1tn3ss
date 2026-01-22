#pragma once

#include <cstddef>

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

} // namespace w1::h00k::memory
