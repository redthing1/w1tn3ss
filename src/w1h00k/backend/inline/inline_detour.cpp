#include "w1h00k/backend/inline/inline_detour.hpp"

#include <cstring>

#include "w1h00k/reloc/reloc_common.hpp"

namespace w1::h00k::backend::inline_hook {
namespace {

arch_kind classify_arch(const w1::arch::arch_spec& spec) {
  switch (spec.arch_mode) {
    case w1::arch::mode::x86_32:
      return arch_kind::x86_32;
    case w1::arch::mode::x86_64:
      return arch_kind::x86_64;
    case w1::arch::mode::aarch64:
      return arch_kind::arm64;
    default:
      return arch_kind::unknown;
  }
}

void append_u32(std::vector<uint8_t>& out, uint32_t value) {
  const size_t offset = out.size();
  out.resize(offset + sizeof(value));
  std::memcpy(out.data() + offset, &value, sizeof(value));
}

void append_u64(std::vector<uint8_t>& out, uint64_t value) {
  const size_t offset = out.size();
  out.resize(offset + sizeof(value));
  std::memcpy(out.data() + offset, &value, sizeof(value));
}

uint32_t arm64_encode_ldr_literal(uint8_t rt, int32_t imm19) {
  return 0x58000000u | ((static_cast<uint32_t>(imm19) & 0x7FFFFu) << 5) | (rt & 0x1Fu);
}

uint32_t arm64_encode_br(uint8_t rn) { return 0xD61F0000u | ((rn & 0x1Fu) << 5); }

bool emit_x86_rel32_jump(std::vector<uint8_t>& out, uint64_t from, uint64_t to) {
  const int64_t disp = static_cast<int64_t>(to) - static_cast<int64_t>(from + 5);
  if (!reloc::detail::fits_signed(disp, 32)) {
    return false;
  }
  out.push_back(0xE9);
  const int32_t imm = static_cast<int32_t>(disp);
  append_u32(out, static_cast<uint32_t>(imm));
  return true;
}

void emit_x86_abs_jump(std::vector<uint8_t>& out, uint64_t to) {
  out.push_back(0xFF);
  out.push_back(0x25);
  out.insert(out.end(), {0x00, 0x00, 0x00, 0x00});
  append_u64(out, to);
}

void emit_arm64_abs_jump(std::vector<uint8_t>& out, uint64_t to) {
  constexpr uint8_t scratch = 16;
  constexpr int32_t imm19 = 2;
  append_u32(out, arm64_encode_ldr_literal(scratch, imm19));
  append_u32(out, arm64_encode_br(scratch));
  append_u64(out, to);
}

std::vector<uint8_t> nop_bytes_for_arch(arch_kind kind) {
  switch (kind) {
    case arch_kind::arm64:
      return {0x1F, 0x20, 0x03, 0xD5};
    case arch_kind::x86_32:
    case arch_kind::x86_64:
      return {0x90};
    default:
      return {};
  }
}

bool arm64_patch_crosses_return(const uint8_t* bytes, size_t size) {
  if (!bytes || size < 4) {
    return false;
  }
  const uint32_t ret_inst = 0xD65F03C0u;
  const uint32_t nop_inst = 0xD503201Fu;
  for (size_t offset = 0; offset + 4 <= size; offset += 4) {
    uint32_t inst = 0;
    std::memcpy(&inst, bytes + offset, sizeof(inst));
    if (inst != ret_inst) {
      continue;
    }
    for (size_t tail = offset + 4; tail + 4 <= size; tail += 4) {
      uint32_t tail_inst = 0;
      std::memcpy(&tail_inst, bytes + tail, sizeof(tail_inst));
      if (tail_inst != nop_inst) {
        return true;
      }
    }
    break;
  }
  return false;
}

} // namespace

detour_plan plan_for(const w1::arch::arch_spec& spec, uint64_t from, uint64_t to) {
  detour_plan plan{};
  plan.arch = classify_arch(spec);
  switch (plan.arch) {
    case arch_kind::x86_32:
      plan.kind = detour_kind::rel32;
      plan.min_patch = 5;
      plan.tail_size = 5;
      break;
    case arch_kind::x86_64: {
      const int64_t disp = static_cast<int64_t>(to) - static_cast<int64_t>(from + 5);
      if (reloc::detail::fits_signed(disp, 32)) {
        plan.kind = detour_kind::rel32;
        plan.min_patch = 5;
      } else {
        plan.kind = detour_kind::absolute;
        plan.min_patch = 14;
      }
      plan.tail_size = 14;
      break;
    }
    case arch_kind::arm64:
      plan.kind = detour_kind::absolute;
      plan.min_patch = 16;
      plan.tail_size = 16;
      break;
    default:
      break;
  }
  return plan;
}

bool build_detour_patch(const detour_plan& plan, uint64_t from, uint64_t to, size_t patch_size,
                        std::vector<uint8_t>& out) {
  out.clear();
  switch (plan.arch) {
    case arch_kind::x86_32:
      if (!emit_x86_rel32_jump(out, from, to)) {
        return false;
      }
      break;
    case arch_kind::x86_64:
      if (plan.kind == detour_kind::rel32) {
        if (!emit_x86_rel32_jump(out, from, to)) {
          return false;
        }
      } else {
        emit_x86_abs_jump(out, to);
      }
      break;
    case arch_kind::arm64:
      emit_arm64_abs_jump(out, to);
      break;
    default:
      return false;
  }

  if (out.size() > patch_size) {
    return false;
  }

  auto nops = nop_bytes_for_arch(plan.arch);
  while (out.size() < patch_size) {
    out.insert(out.end(), nops.begin(), nops.end());
  }
  return true;
}

bool append_trampoline_tail(const detour_plan& plan, uint64_t tramp_end, uint64_t resume_addr,
                            std::vector<uint8_t>& out) {
  switch (plan.arch) {
    case arch_kind::x86_32:
      return emit_x86_rel32_jump(out, tramp_end, resume_addr);
    case arch_kind::x86_64:
      emit_x86_abs_jump(out, resume_addr);
      return true;
    case arch_kind::arm64:
      emit_arm64_abs_jump(out, resume_addr);
      return true;
    default:
      return false;
  }
}

bool prologue_safe(const detour_plan& plan, const uint8_t* bytes, size_t size) {
  if (plan.arch == arch_kind::arm64) {
    return !arm64_patch_crosses_return(bytes, size);
  }
  return true;
}

} // namespace w1::h00k::backend::inline_hook
