#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "w1base/arch_spec.hpp"

namespace w1::h00k::backend::inline_hook {

enum class arch_kind {
  x86_32,
  x86_64,
  arm64,
  unknown
};

enum class detour_kind {
  rel32,
  absolute
};

struct detour_plan {
  arch_kind arch = arch_kind::unknown;
  detour_kind kind = detour_kind::absolute;
  size_t min_patch = 0;
  size_t tail_size = 0;
};

detour_plan plan_for(const w1::arch::arch_spec& spec, uint64_t from, uint64_t to);
bool build_detour_patch(const detour_plan& plan, uint64_t from, uint64_t to, size_t patch_size,
                        std::vector<uint8_t>& out);
bool append_trampoline_tail(const detour_plan& plan, uint64_t tramp_end, uint64_t resume_addr,
                            std::vector<uint8_t>& out);
bool prologue_safe(const detour_plan& plan, const uint8_t* bytes, size_t size);

} // namespace w1::h00k::backend::inline_hook
