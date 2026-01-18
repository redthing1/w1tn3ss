#include "asmr/asmr.hpp"

#include <capstone/arm64.h>
#include <capstone/x86.h>

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

#include "utils/hex_utils.hpp"

namespace p1ll::asmr::heur {

namespace {

struct policy_params {
  size_t min_fixed_bytes = 0;
  size_t max_instructions = 0;
};

policy_params params_for(policy policy_value) {
  switch (policy_value) {
  case policy::strict:
    return policy_params{8, 20};
  case policy::balanced:
    return policy_params{12, 20};
  case policy::durable:
    return policy_params{16, 20};
  }
  return policy_params{12, 20};
}

void mask_range(std::vector<uint8_t>& mask, size_t offset, size_t size) {
  if (size == 0 || mask.empty()) {
    return;
  }
  if (offset >= mask.size()) {
    return;
  }
  size_t end = std::min(mask.size(), offset + size);
  for (size_t i = offset; i < end; ++i) {
    mask[i] = 0;
  }
}

bool only_register_operands(const instruction& inst) {
  if (inst.operand_details.empty()) {
    return false;
  }
  for (const auto& op : inst.operand_details) {
    if (op.kind != operand_kind::reg) {
      return false;
    }
  }
  return true;
}

bool has_rip_relative_operand(const instruction& inst) {
  for (const auto& op : inst.operand_details) {
    if (op.kind == operand_kind::mem && op.mem_base == X86_REG_RIP) {
      return true;
    }
  }
  return false;
}

bool has_arm64_immediate(const instruction& inst) {
  for (const auto& op : inst.operand_details) {
    if (op.kind == operand_kind::imm || op.kind == operand_kind::mem) {
      return true;
    }
  }
  return false;
}

std::string normalize_arm64_operands(const std::string& op_str) {
  if (op_str.empty()) {
    return {};
  }

  std::string output;
  output.reserve(op_str.size());

  for (size_t i = 0; i < op_str.size();) {
    if (op_str[i] != '#') {
      output.push_back(op_str[i]);
      ++i;
      continue;
    }

    output += "#0";
    ++i;

    if (i < op_str.size() && (op_str[i] == '+' || op_str[i] == '-')) {
      ++i;
    }

    if (i + 1 < op_str.size() && op_str[i] == '0' && (op_str[i + 1] == 'x' || op_str[i + 1] == 'X')) {
      i += 2;
      while (i < op_str.size() && std::isxdigit(static_cast<unsigned char>(op_str[i]))) {
        ++i;
      }
    } else {
      while (i < op_str.size() && std::isdigit(static_cast<unsigned char>(op_str[i]))) {
        ++i;
      }
    }
  }

  return output;
}

std::vector<uint8_t> mask_x86_instruction(const instruction& inst, policy policy_value) {
  std::vector<uint8_t> mask(inst.bytes.size(), 1);

  bool rip_relative = has_rip_relative_operand(inst);
  bool only_regs = only_register_operands(inst);

  if (policy_value == policy::strict) {
    if (inst.is_branch_relative) {
      mask_range(mask, inst.encoding_info.imm_offset, inst.encoding_info.imm_size);
    }
    if (rip_relative) {
      mask_range(mask, inst.encoding_info.disp_offset, inst.encoding_info.disp_size);
    }
  } else {
    mask_range(mask, inst.encoding_info.imm_offset, inst.encoding_info.imm_size);
    mask_range(mask, inst.encoding_info.disp_offset, inst.encoding_info.disp_size);
  }

  if (policy_value == policy::durable && only_regs && inst.encoding_info.modrm_offset > 0) {
    mask_range(mask, inst.encoding_info.modrm_offset, 1);
  }

  return mask;
}

std::vector<uint8_t> mask_arm64_instruction(const instruction& inst, const context& ctx, policy policy_value) {
  std::vector<uint8_t> mask(inst.bytes.size(), 1);

  bool should_normalize = false;
  if (policy_value == policy::strict) {
    should_normalize = inst.is_branch_relative || inst.id == ARM64_INS_ADR || inst.id == ARM64_INS_ADRP;
  } else {
    should_normalize = true;
  }

  if (!should_normalize) {
    return mask;
  }

  std::string normalized_ops = normalize_arm64_operands(inst.operands);
  std::string text = inst.mnemonic;
  if (!normalized_ops.empty()) {
    text += " ";
    text += normalized_ops;
  }

  auto assembled = ctx.assemble(text, inst.address);
  if (!assembled.ok() || assembled.value.size() != inst.bytes.size()) {
    if (policy_value == policy::durable && has_arm64_immediate(inst)) {
      std::fill(mask.begin(), mask.end(), 0);
    }
    return mask;
  }

  bool any_diff = false;
  for (size_t i = 0; i < inst.bytes.size(); ++i) {
    if (assembled.value[i] != inst.bytes[i]) {
      mask[i] = 0;
      any_diff = true;
    }
  }

  if (!any_diff && policy_value == policy::durable && has_arm64_immediate(inst)) {
    std::fill(mask.begin(), mask.end(), 0);
  }

  return mask;
}

void append_pattern(std::string& output, const std::vector<uint8_t>& bytes, const std::vector<uint8_t>& mask) {
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (!output.empty()) {
      output += " ";
    }
    if (i < mask.size() && mask[i] == 0) {
      output += "??";
    } else {
      output += p1ll::utils::to_hex_string(bytes[i]);
    }
  }
}

std::string format_pretty_line(const instruction& inst, const std::vector<uint8_t>& mask) {
  std::string line;
  for (size_t i = 0; i < inst.bytes.size(); ++i) {
    if (!line.empty()) {
      line += " ";
    }
    if (i < mask.size() && mask[i] == 0) {
      line += "??";
    } else {
      line += p1ll::utils::to_hex_string(inst.bytes[i]);
    }
  }

  if (!inst.mnemonic.empty()) {
    line += "  // ";
    line += inst.mnemonic;
    if (!inst.operands.empty()) {
      line += " ";
      line += inst.operands;
    }
  }

  return line;
}

} // namespace

engine::result<signature> code_signature(
    std::span<const uint8_t> bytes, uint64_t address, const engine::platform::platform_key& platform,
    policy policy_value
) {
  if (bytes.empty()) {
    return engine::error_result<signature>(engine::error_code::invalid_argument, "signature input is empty");
  }

  auto ctx = context::for_platform(platform);
  if (!ctx.ok()) {
    return engine::error_result<signature>(ctx.status_info.code, ctx.status_info.message);
  }

  auto disassembly = ctx.value.disassemble(bytes, address);
  if (!disassembly.ok()) {
    return engine::error_result<signature>(disassembly.status_info.code, disassembly.status_info.message);
  }

  if (disassembly.value.empty()) {
    return engine::error_result<signature>(engine::error_code::not_found, "no instructions decoded");
  }

  policy_params params = params_for(policy_value);

  signature output;
  size_t fixed_bytes = 0;
  size_t instruction_count = 0;

  for (const auto& inst : disassembly.value) {
    if (instruction_count >= params.max_instructions) {
      break;
    }

    std::vector<uint8_t> mask;
    if (ctx.value.architecture() == arch::arm64) {
      mask = mask_arm64_instruction(inst, ctx.value, policy_value);
    } else {
      mask = mask_x86_instruction(inst, policy_value);
    }

    append_pattern(output.pattern, inst.bytes, mask);

    if (!output.pretty.empty()) {
      output.pretty += "\n";
    }
    output.pretty += format_pretty_line(inst, mask);

    for (auto value : mask) {
      if (value != 0) {
        ++fixed_bytes;
      }
    }

    ++instruction_count;
    if (fixed_bytes >= params.min_fixed_bytes) {
      break;
    }
  }

  output.instruction_count = instruction_count;
  output.fixed_bytes = fixed_bytes;
  return engine::ok_result(output);
}

} // namespace p1ll::asmr::heur
