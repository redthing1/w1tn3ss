#pragma once

#include <cstddef>
#include <cstdint>

#include "w1h00k/reloc/relocator.hpp"

namespace w1::asmr {
class disasm_context;
}

namespace w1::h00k::reloc::detail {

reloc_result relocate_x86(const w1::asmr::disasm_context& disasm, const void* target, size_t min_patch_size,
                          uint64_t trampoline_address);

} // namespace w1::h00k::reloc::detail
