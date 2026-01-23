#pragma once

#include <cstddef>
#include <vector>

#include "w1base/arch_spec.hpp"

namespace w1::h00k::reloc {

enum class reloc_error {
  ok,
  invalid_target,
  invalid_request,
  unsupported_arch,
  decode_failed,
  insufficient_bytes,
  missing_trampoline,
  unsupported_instruction,
  out_of_range
};

const char* to_string(reloc_error error);

struct reloc_result {
  std::vector<uint8_t> trampoline_bytes{};
  size_t patch_size = 0;
  reloc_error error = reloc_error::invalid_request;

  bool ok() const { return error == reloc_error::ok; }
};

reloc_result relocate(const void* target, size_t min_patch_size);
reloc_result relocate(const void* target, size_t min_patch_size, uint64_t trampoline_address);
reloc_result relocate(const void* target, size_t min_patch_size, uint64_t trampoline_address,
                      const w1::arch::arch_spec& arch);
size_t max_trampoline_size(size_t min_patch_size, const w1::arch::arch_spec& arch);

} // namespace w1::h00k::reloc
