#include "w1h00k/reloc/arm64.hpp"

#include <span>

#include "w1asmr/asmr.hpp"
#include "w1h00k/reloc/common.hpp"

namespace w1::h00k::reloc::detail {
namespace {

uint32_t read_u32_le(const uint8_t* bytes) {
  uint32_t value = 0;
  std::memcpy(&value, bytes, sizeof(value));
  return value;
}

void write_u32_le(std::vector<uint8_t>& out, size_t offset, uint32_t value) {
  std::memcpy(out.data() + offset, &value, sizeof(value));
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

bool arm64_is_b(uint32_t inst) { return (inst & 0xFC000000u) == 0x14000000u; }
bool arm64_is_bl(uint32_t inst) { return (inst & 0xFC000000u) == 0x94000000u; }
bool arm64_is_bcond(uint32_t inst) { return (inst & 0xFF000010u) == 0x54000000u; }
bool arm64_is_cbz(uint32_t inst) { return (inst & 0x7F000000u) == 0x34000000u; }
bool arm64_is_cbnz(uint32_t inst) { return (inst & 0x7F000000u) == 0x35000000u; }
bool arm64_is_tbz(uint32_t inst) { return (inst & 0x7F000000u) == 0x36000000u; }
bool arm64_is_tbnz(uint32_t inst) { return (inst & 0x7F000000u) == 0x37000000u; }
bool arm64_is_adr(uint32_t inst) { return (inst & 0x9F000000u) == 0x10000000u; }
bool arm64_is_adrp(uint32_t inst) { return (inst & 0x9F000000u) == 0x90000000u; }

enum class arm64_fixup_kind {
  none,
  b,
  bl,
  bcond,
  cbz,
  cbnz,
  tbz,
  tbnz,
  adr,
  adrp
};

arm64_fixup_kind classify_arm64(uint32_t inst) {
  if (arm64_is_b(inst)) {
    return arm64_fixup_kind::b;
  }
  if (arm64_is_bl(inst)) {
    return arm64_fixup_kind::bl;
  }
  if (arm64_is_bcond(inst)) {
    return arm64_fixup_kind::bcond;
  }
  if (arm64_is_cbz(inst)) {
    return arm64_fixup_kind::cbz;
  }
  if (arm64_is_cbnz(inst)) {
    return arm64_fixup_kind::cbnz;
  }
  if (arm64_is_tbz(inst)) {
    return arm64_fixup_kind::tbz;
  }
  if (arm64_is_tbnz(inst)) {
    return arm64_fixup_kind::tbnz;
  }
  if (arm64_is_adr(inst)) {
    return arm64_fixup_kind::adr;
  }
  if (arm64_is_adrp(inst)) {
    return arm64_fixup_kind::adrp;
  }
  return arm64_fixup_kind::none;
}

uint64_t arm64_branch_target(uint32_t inst, uint64_t pc) {
  if (arm64_is_b(inst) || arm64_is_bl(inst)) {
    const int64_t imm26 = detail::sign_extend(inst & 0x03FFFFFFu, 26) << 2;
    return pc + static_cast<uint64_t>(imm26);
  }
  if (arm64_is_bcond(inst) || arm64_is_cbz(inst) || arm64_is_cbnz(inst)) {
    const int64_t imm19 = detail::sign_extend((inst >> 5) & 0x7FFFFu, 19) << 2;
    return pc + static_cast<uint64_t>(imm19);
  }
  if (arm64_is_tbz(inst) || arm64_is_tbnz(inst)) {
    const int64_t imm14 = detail::sign_extend((inst >> 5) & 0x3FFFu, 14) << 2;
    return pc + static_cast<uint64_t>(imm14);
  }
  if (arm64_is_adr(inst)) {
    const uint32_t immlo = (inst >> 29) & 0x3u;
    const uint32_t immhi = (inst >> 5) & 0x7FFFFu;
    const int64_t imm = detail::sign_extend((immhi << 2) | immlo, 21);
    return pc + static_cast<uint64_t>(imm);
  }
  if (arm64_is_adrp(inst)) {
    const uint32_t immlo = (inst >> 29) & 0x3u;
    const uint32_t immhi = (inst >> 5) & 0x7FFFFu;
    const int64_t imm = detail::sign_extend((immhi << 2) | immlo, 21) << 12;
    const uint64_t page = pc & ~0xFFFULL;
    return page + static_cast<uint64_t>(imm);
  }
  return pc;
}

bool arm64_patch_imm26(uint32_t& inst, int64_t offset) {
  if (offset % 4 != 0) {
    return false;
  }
  const int64_t imm = offset >> 2;
  if (!detail::fits_signed(imm, 26)) {
    return false;
  }
  inst = (inst & 0xFC000000u) | (static_cast<uint32_t>(imm) & 0x03FFFFFFu);
  return true;
}

bool arm64_patch_imm19(uint32_t& inst, int64_t offset) {
  if (offset % 4 != 0) {
    return false;
  }
  const int64_t imm = offset >> 2;
  if (!detail::fits_signed(imm, 19)) {
    return false;
  }
  inst &= ~(0x7FFFFu << 5);
  inst |= (static_cast<uint32_t>(imm) & 0x7FFFFu) << 5;
  return true;
}

bool arm64_patch_imm14(uint32_t& inst, int64_t offset) {
  if (offset % 4 != 0) {
    return false;
  }
  const int64_t imm = offset >> 2;
  if (!detail::fits_signed(imm, 14)) {
    return false;
  }
  inst &= ~(0x3FFFu << 5);
  inst |= (static_cast<uint32_t>(imm) & 0x3FFFu) << 5;
  return true;
}

bool arm64_patch_adr(uint32_t& inst, int64_t offset) {
  if (!detail::fits_signed(offset, 21)) {
    return false;
  }
  uint32_t imm = static_cast<uint32_t>(offset) & 0x1FFFFF;
  uint32_t immlo = imm & 0x3u;
  uint32_t immhi = (imm >> 2) & 0x7FFFFu;
  inst &= ~((0x3u << 29) | (0x7FFFFu << 5));
  inst |= (immlo << 29) | (immhi << 5);
  return true;
}

bool arm64_patch_adrp(uint32_t& inst, int64_t page_delta) {
  const int64_t imm = page_delta >> 12;
  if (!detail::fits_signed(imm, 21)) {
    return false;
  }
  uint32_t imm21 = static_cast<uint32_t>(imm) & 0x1FFFFF;
  uint32_t immlo = imm21 & 0x3u;
  uint32_t immhi = (imm21 >> 2) & 0x7FFFFu;
  inst &= ~((0x3u << 29) | (0x7FFFFu << 5));
  inst |= (immlo << 29) | (immhi << 5);
  return true;
}

uint32_t arm64_encode_ldr_literal(uint8_t rt, int32_t imm19) {
  return 0x58000000u | ((static_cast<uint32_t>(imm19) & 0x7FFFFu) << 5) | (rt & 0x1Fu);
}

uint32_t arm64_encode_br(uint8_t rn) { return 0xD61F0000u | ((rn & 0x1Fu) << 5); }
uint32_t arm64_encode_blr(uint8_t rn) { return 0xD63F0000u | ((rn & 0x1Fu) << 5); }

bool emit_arm64_ldr_literal(std::vector<uint8_t>& out, uint8_t rt, uint64_t value) {
  const int32_t imm19 = 1; // literal at +4 bytes
  if (!detail::fits_signed(imm19, 19)) {
    return false;
  }
  append_u32(out, arm64_encode_ldr_literal(rt, imm19));
  append_u64(out, value);
  return true;
}

bool emit_arm64_abs_branch(std::vector<uint8_t>& out, uint64_t target, bool is_call) {
  constexpr uint8_t scratch = 16;
  const int32_t imm19 = 2; // literal at +8 bytes
  append_u32(out, arm64_encode_ldr_literal(scratch, imm19));
  append_u32(out, is_call ? arm64_encode_blr(scratch) : arm64_encode_br(scratch));
  append_u64(out, target);
  return true;
}

bool emit_arm64_cond_stub(std::vector<uint8_t>& out, uint32_t inst, uint64_t target) {
  constexpr int64_t stub_len = 16;
  constexpr int64_t skip = stub_len;
  uint32_t skip_inst = inst;
  if (arm64_is_bcond(inst)) {
    const uint32_t cond = inst & 0xFu;
    skip_inst = (inst & ~0xFu) | ((cond ^ 1u) & 0xFu);
    if (!arm64_patch_imm19(skip_inst, skip)) {
      return false;
    }
  } else if (arm64_is_cbz(inst) || arm64_is_cbnz(inst)) {
    skip_inst = inst ^ 0x01000000u;
    if (!arm64_patch_imm19(skip_inst, skip)) {
      return false;
    }
  } else if (arm64_is_tbz(inst) || arm64_is_tbnz(inst)) {
    skip_inst = inst ^ 0x01000000u;
    if (!arm64_patch_imm14(skip_inst, skip)) {
      return false;
    }
  } else {
    return false;
  }

  append_u32(out, skip_inst);
  return emit_arm64_abs_branch(out, target, false);
}

} // namespace

reloc_result relocate_arm64(const w1::asmr::disasm_context& disasm, const void* target, size_t min_patch_size,
                            uint64_t trampoline_address) {
  auto fail = [](reloc_error error) {
    reloc_result out{};
    out.error = error;
    return out;
  };

  reloc_result result{};
  result.error = reloc_error::ok;

  auto bytes = std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(target), kMaxPatchBytes);
  auto decoded = disasm.disassemble(bytes, reinterpret_cast<uint64_t>(target));
  if (!decoded.ok()) {
    return fail(reloc_error::decode_failed);
  }

  size_t consumed = 0;
  for (const auto& insn : decoded.value) {
    if (insn.bytes.empty()) {
      break;
    }

    const size_t insn_len = insn.bytes.size();
    if (insn_len != 4) {
      return fail(reloc_error::unsupported_instruction);
    }

    const size_t out_base = result.trampoline_bytes.size();
    result.trampoline_bytes.insert(result.trampoline_bytes.end(), insn.bytes.begin(), insn.bytes.end());

    uint32_t inst = read_u32_le(insn.bytes.data());
    const arm64_fixup_kind kind = classify_arm64(inst);
    const bool needs_fixup = kind != arm64_fixup_kind::none;

    if (needs_fixup) {
      if (trampoline_address == 0) {
        return fail(reloc_error::missing_trampoline);
      }
      const uint64_t insn_addr = insn.address;
      const uint64_t new_addr = trampoline_address + out_base;
      const uint64_t target_addr = arm64_branch_target(inst, insn_addr);

      if (kind == arm64_fixup_kind::b || kind == arm64_fixup_kind::bl) {
        const int64_t offset = static_cast<int64_t>(target_addr) - static_cast<int64_t>(new_addr);
        if (!arm64_patch_imm26(inst, offset)) {
          result.trampoline_bytes.resize(out_base);
          const bool is_call = kind == arm64_fixup_kind::bl;
          if (!emit_arm64_abs_branch(result.trampoline_bytes, target_addr, is_call)) {
            return fail(reloc_error::out_of_range);
          }
          consumed += insn_len;
          if (consumed >= min_patch_size) {
            break;
          }
          continue;
        }
      } else if (kind == arm64_fixup_kind::bcond || kind == arm64_fixup_kind::cbz || kind == arm64_fixup_kind::cbnz) {
        const int64_t offset = static_cast<int64_t>(target_addr) - static_cast<int64_t>(new_addr);
        if (!arm64_patch_imm19(inst, offset)) {
          result.trampoline_bytes.resize(out_base);
          if (!emit_arm64_cond_stub(result.trampoline_bytes, inst, target_addr)) {
            return fail(reloc_error::out_of_range);
          }
          consumed += insn_len;
          if (consumed >= min_patch_size) {
            break;
          }
          continue;
        }
      } else if (kind == arm64_fixup_kind::tbz || kind == arm64_fixup_kind::tbnz) {
        const int64_t offset = static_cast<int64_t>(target_addr) - static_cast<int64_t>(new_addr);
        if (!arm64_patch_imm14(inst, offset)) {
          result.trampoline_bytes.resize(out_base);
          if (!emit_arm64_cond_stub(result.trampoline_bytes, inst, target_addr)) {
            return fail(reloc_error::out_of_range);
          }
          consumed += insn_len;
          if (consumed >= min_patch_size) {
            break;
          }
          continue;
        }
      } else if (kind == arm64_fixup_kind::adr) {
        const int64_t offset = static_cast<int64_t>(target_addr) - static_cast<int64_t>(new_addr);
        if (!arm64_patch_adr(inst, offset)) {
          result.trampoline_bytes.resize(out_base);
          const uint8_t rt = static_cast<uint8_t>(inst & 0x1Fu);
          if (!emit_arm64_ldr_literal(result.trampoline_bytes, rt, target_addr)) {
            return fail(reloc_error::out_of_range);
          }
          consumed += insn_len;
          if (consumed >= min_patch_size) {
            break;
          }
          continue;
        }
      } else if (kind == arm64_fixup_kind::adrp) {
        const uint64_t target_page = target_addr & ~0xFFFULL;
        const uint64_t new_page = new_addr & ~0xFFFULL;
        const int64_t page_delta = static_cast<int64_t>(target_page) - static_cast<int64_t>(new_page);
        if (!arm64_patch_adrp(inst, page_delta)) {
          result.trampoline_bytes.resize(out_base);
          const uint8_t rt = static_cast<uint8_t>(inst & 0x1Fu);
          if (!emit_arm64_ldr_literal(result.trampoline_bytes, rt, target_page)) {
            return fail(reloc_error::out_of_range);
          }
          consumed += insn_len;
          if (consumed >= min_patch_size) {
            break;
          }
          continue;
        }
      }

      write_u32_le(result.trampoline_bytes, out_base, inst);
    }

    consumed += insn_len;
    if (consumed >= min_patch_size) {
      break;
    }
  }

  if (consumed < min_patch_size) {
    return fail(reloc_error::insufficient_bytes);
  }

  result.patch_size = consumed;
  return result;
}

} // namespace w1::h00k::reloc::detail
