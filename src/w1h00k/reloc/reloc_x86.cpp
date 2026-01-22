#include "w1h00k/reloc/reloc_x86.hpp"

#include <span>

#include "w1asmr/asmr.hpp"
#include "w1base/arch_spec.hpp"
#include "w1h00k/reloc/reloc_common.hpp"

namespace w1::h00k::reloc::detail {
namespace {

enum class branch_kind {
  none,
  jmp,
  call,
  jcc
};

bool has_pc_relative_mem(const w1::asmr::instruction& insn) {
  for (const auto& operand : insn.operand_details) {
    if (operand.kind != w1::asmr::operand_kind::mem) {
      continue;
    }
    if (operand.is_pc_relative) {
      return true;
    }
  }
  return false;
}

} // namespace

branch_kind classify_branch(const w1::asmr::instruction& insn, uint8_t& cond_out) {
  cond_out = 0;
  if (insn.bytes.empty()) {
    return branch_kind::none;
  }
  const uint8_t op0 = insn.bytes[0];
  if (op0 == 0xE9) {
    return branch_kind::jmp;
  }
  if (op0 == 0xE8) {
    return branch_kind::call;
  }
  if (op0 >= 0x70 && op0 <= 0x7F) {
    cond_out = static_cast<uint8_t>(op0 & 0x0F);
    return branch_kind::jcc;
  }
  if (op0 == 0x0F && insn.bytes.size() >= 2) {
    const uint8_t op1 = insn.bytes[1];
    if (op1 >= 0x80 && op1 <= 0x8F) {
      cond_out = static_cast<uint8_t>(op1 & 0x0F);
      return branch_kind::jcc;
    }
  }
  return branch_kind::none;
}

bool emit_abs_branch(std::vector<uint8_t>& out, uint64_t trampoline_address, uint64_t target, bool is_call,
                     bool is_x64) {
  if (is_x64) {
    out.push_back(0xFF);
    out.push_back(is_call ? 0x15 : 0x25);
    out.insert(out.end(), {0x00, 0x00, 0x00, 0x00});
    for (int i = 0; i < 8; ++i) {
      out.push_back(static_cast<uint8_t>((target >> (i * 8)) & 0xFFu));
    }
    return true;
  }

  const uint64_t literal_addr = trampoline_address + out.size() + 6;
  if (literal_addr > 0xFFFFFFFFu) {
    return false;
  }
  out.push_back(0xFF);
  out.push_back(is_call ? 0x15 : 0x25);
  const uint32_t addr32 = static_cast<uint32_t>(literal_addr);
  for (int i = 0; i < 4; ++i) {
    out.push_back(static_cast<uint8_t>((addr32 >> (i * 8)) & 0xFFu));
  }
  const uint32_t target32 = static_cast<uint32_t>(target & 0xFFFFFFFFu);
  for (int i = 0; i < 4; ++i) {
    out.push_back(static_cast<uint8_t>((target32 >> (i * 8)) & 0xFFu));
  }
  return true;
}

bool emit_jcc_stub(std::vector<uint8_t>& out, uint64_t trampoline_address, uint64_t target, uint8_t cond,
                   bool is_x64) {
  const uint8_t inverted = static_cast<uint8_t>(cond ^ 0x1);
  const size_t stub_len = is_x64 ? 14 : 10;
  if (stub_len > 0x7F) {
    return false;
  }
  out.push_back(static_cast<uint8_t>(0x70 | inverted));
  out.push_back(static_cast<uint8_t>(stub_len));
  return emit_abs_branch(out, trampoline_address, target, false, is_x64);
}

reloc_result relocate_x86(const w1::asmr::disasm_context& disasm, const void* target, size_t min_patch_size,
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
  const bool is_x64 = disasm.architecture().arch_mode == w1::arch::mode::x86_64;
  for (const auto& insn : decoded.value) {
    if (insn.bytes.empty()) {
      break;
    }

    const size_t insn_len = insn.bytes.size();
    const size_t out_base = result.trampoline_bytes.size();
    const bool pc_relative_mem = has_pc_relative_mem(insn);
    const bool branch_relative = insn.is_branch_relative;
    uint8_t cond = 0;
    branch_kind kind = branch_relative ? classify_branch(insn, cond) : branch_kind::none;

    if (branch_relative && kind == branch_kind::none) {
      return fail(reloc_error::unsupported_instruction);
    }

    if (pc_relative_mem || branch_relative) {
      if (trampoline_address == 0) {
        return fail(reloc_error::missing_trampoline);
      }
    }

    result.trampoline_bytes.insert(result.trampoline_bytes.end(), insn.bytes.begin(), insn.bytes.end());

    if (branch_relative) {
      if (insn.encoding_info.imm_size == 0) {
        return fail(reloc_error::unsupported_instruction);
      }
      const int64_t orig_disp = read_signed_le(insn.bytes.data() + insn.encoding_info.imm_offset,
                                               insn.encoding_info.imm_size);
      const uint64_t target_addr = insn.address + insn_len + static_cast<int64_t>(orig_disp);
      const uint64_t insn_end = trampoline_address + out_base + insn_len;
      const int64_t new_disp = static_cast<int64_t>(target_addr) - static_cast<int64_t>(insn_end);

      if (!write_signed_le(result.trampoline_bytes, out_base + insn.encoding_info.imm_offset,
                           insn.encoding_info.imm_size, new_disp)) {
        result.trampoline_bytes.resize(out_base);
        bool stub_ok = false;
        if (kind == branch_kind::jmp || kind == branch_kind::call) {
          stub_ok = emit_abs_branch(result.trampoline_bytes, trampoline_address, target_addr, kind == branch_kind::call,
                                    is_x64);
        } else if (kind == branch_kind::jcc) {
          stub_ok = emit_jcc_stub(result.trampoline_bytes, trampoline_address, target_addr, cond, is_x64);
        }
        if (!stub_ok) {
          return fail(reloc_error::out_of_range);
        }
      }
    }

    if (pc_relative_mem) {
      if (insn.encoding_info.disp_size == 0) {
        return fail(reloc_error::unsupported_instruction);
      }
      const int64_t orig_disp = read_signed_le(insn.bytes.data() + insn.encoding_info.disp_offset,
                                               insn.encoding_info.disp_size);
      const uint64_t target_addr = insn.address + insn_len + static_cast<int64_t>(orig_disp);
      const uint64_t insn_end = trampoline_address + out_base + insn_len;
      const int64_t new_disp = static_cast<int64_t>(target_addr) - static_cast<int64_t>(insn_end);
      if (!write_signed_le(result.trampoline_bytes, out_base + insn.encoding_info.disp_offset,
                           insn.encoding_info.disp_size, new_disp)) {
        return fail(reloc_error::out_of_range);
      }
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
