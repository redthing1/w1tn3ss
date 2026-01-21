#pragma once

#include <cstddef>
#include <vector>

namespace w1::h00k::reloc {

struct reloc_result {
  std::vector<uint8_t> trampoline_bytes{};
  size_t patch_size = 0;
};

reloc_result relocate(const void* target, size_t min_patch_size);

} // namespace w1::h00k::reloc
