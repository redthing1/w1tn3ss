#include "w1h00k/reloc/reloc_x86.hpp"

#include <span>

#include "w1asmr/asmr.hpp"
#include "w1h00k/reloc/reloc_common.hpp"

namespace w1::h00k::reloc::detail {
namespace {

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
  for (const auto& insn : decoded.value) {
    if (insn.bytes.empty()) {
      break;
    }

    const size_t insn_len = insn.bytes.size();
    const size_t out_base = result.trampoline_bytes.size();
    result.trampoline_bytes.insert(result.trampoline_bytes.end(), insn.bytes.begin(), insn.bytes.end());

    const bool pc_relative_mem = has_pc_relative_mem(insn);
    const bool branch_relative = insn.is_branch_relative;
    if (pc_relative_mem || branch_relative) {
      if (trampoline_address == 0) {
        return fail(reloc_error::missing_trampoline);
      }
      const uint64_t insn_end = trampoline_address + out_base + insn_len;

      if (branch_relative) {
        if (insn.encoding_info.imm_size == 0) {
          return fail(reloc_error::unsupported_instruction);
        }
        const int64_t orig_disp = read_signed_le(insn.bytes.data() + insn.encoding_info.imm_offset,
                                                 insn.encoding_info.imm_size);
        const uint64_t target_addr = insn.address + insn_len + static_cast<int64_t>(orig_disp);
        const int64_t new_disp = static_cast<int64_t>(target_addr) - static_cast<int64_t>(insn_end);
        if (!write_signed_le(result.trampoline_bytes, out_base + insn.encoding_info.imm_offset,
                             insn.encoding_info.imm_size, new_disp)) {
          return fail(reloc_error::out_of_range);
        }
      }

      if (pc_relative_mem) {
        if (insn.encoding_info.disp_size == 0) {
          return fail(reloc_error::unsupported_instruction);
        }
        const int64_t orig_disp = read_signed_le(insn.bytes.data() + insn.encoding_info.disp_offset,
                                                 insn.encoding_info.disp_size);
        const uint64_t target_addr = insn.address + insn_len + static_cast<int64_t>(orig_disp);
        const int64_t new_disp = static_cast<int64_t>(target_addr) - static_cast<int64_t>(insn_end);
        if (!write_signed_le(result.trampoline_bytes, out_base + insn.encoding_info.disp_offset,
                             insn.encoding_info.disp_size, new_disp)) {
          return fail(reloc_error::out_of_range);
        }
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
