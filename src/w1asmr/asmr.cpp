#include "asmr.hpp"

#include <capstone/arm.h>
#include <capstone/arm64.h>
#include <capstone/capstone.h>
#include <capstone/mips.h>
#include <capstone/ppc.h>
#include <capstone/riscv.h>
#include <capstone/sparc.h>
#include <capstone/systemz.h>
#include <capstone/wasm.h>
#include <capstone/x86.h>
#include <keystone/keystone.h>

#include <memory>
#include <string>
#include <utility>

namespace w1::asmr {

namespace {

struct capstone_config {
  cs_arch arch = CS_ARCH_X86;
  cs_mode mode = CS_MODE_64;
  arch_spec normalized{};
};

struct keystone_config {
  ks_arch arch = KS_ARCH_X86;
  ks_mode mode = KS_MODE_64;
  arch_spec normalized{};
};

cs_mode endian_mode(byte_order order) {
  switch (order) {
  case byte_order::big:
    return CS_MODE_BIG_ENDIAN;
  case byte_order::little:
    return CS_MODE_LITTLE_ENDIAN;
  case byte_order::unknown:
    break;
  }
  return static_cast<cs_mode>(0);
}

ks_mode keystone_endian_mode(byte_order order) {
  switch (order) {
  case byte_order::big:
    return KS_MODE_BIG_ENDIAN;
  case byte_order::little:
  case byte_order::unknown:
    break;
  }
  return KS_MODE_LITTLE_ENDIAN;
}

arch_spec normalize_spec(arch_spec spec) {
  if (spec.pointer_bits == 0) {
    spec.pointer_bits = w1::arch::default_pointer_bits(spec.arch_mode);
  }
  if (spec.arch_byte_order == byte_order::unknown) {
    spec.arch_byte_order = w1::arch::default_byte_order(spec.arch_family, spec.arch_mode);
  }
  return spec;
}

result<capstone_config> capstone_config_for(const arch_spec& input) {
  arch_spec spec = normalize_spec(input);
  capstone_config cfg{};
  cfg.normalized = spec;

  if (spec.arch_family == family::x86 && spec.arch_byte_order == byte_order::big) {
    return error_result<capstone_config>(error_code::unsupported, "x86 does not support big endian");
  }
  if ((spec.arch_mode == mode::wasm32 || spec.arch_mode == mode::wasm64) && spec.arch_byte_order == byte_order::big) {
    return error_result<capstone_config>(error_code::unsupported, "wasm does not support big endian");
  }
  if (spec.arch_mode == mode::systemz && spec.arch_byte_order == byte_order::little) {
    return error_result<capstone_config>(error_code::unsupported, "systemz does not support little endian");
  }

  switch (spec.arch_mode) {
  case mode::x86_32:
    cfg.arch = CS_ARCH_X86;
    cfg.mode = CS_MODE_32;
    break;
  case mode::x86_64:
    cfg.arch = CS_ARCH_X86;
    cfg.mode = CS_MODE_64;
    break;
  case mode::arm:
    cfg.arch = CS_ARCH_ARM;
    cfg.mode = static_cast<cs_mode>(CS_MODE_ARM | endian_mode(spec.arch_byte_order));
    break;
  case mode::thumb:
    cfg.arch = CS_ARCH_ARM;
    cfg.mode = static_cast<cs_mode>(CS_MODE_THUMB | endian_mode(spec.arch_byte_order));
    break;
  case mode::aarch64:
#ifdef CAPSTONE_AARCH64_COMPAT_HEADER
    cfg.arch = CS_ARCH_ARM64;
#else
    cfg.arch = CS_ARCH_AARCH64;
#endif
    cfg.mode = endian_mode(spec.arch_byte_order);
    break;
  case mode::riscv32:
    cfg.arch = CS_ARCH_RISCV;
    cfg.mode = static_cast<cs_mode>(CS_MODE_RISCV32 | endian_mode(spec.arch_byte_order));
    break;
  case mode::riscv64:
    cfg.arch = CS_ARCH_RISCV;
    cfg.mode = static_cast<cs_mode>(CS_MODE_RISCV64 | endian_mode(spec.arch_byte_order));
    break;
  case mode::mips32:
    cfg.arch = CS_ARCH_MIPS;
    cfg.mode = static_cast<cs_mode>(CS_MODE_MIPS32 | endian_mode(spec.arch_byte_order));
    break;
  case mode::mips64:
    cfg.arch = CS_ARCH_MIPS;
    cfg.mode = static_cast<cs_mode>(CS_MODE_MIPS64 | endian_mode(spec.arch_byte_order));
    break;
  case mode::ppc32:
    cfg.arch = CS_ARCH_PPC;
    cfg.mode = static_cast<cs_mode>(CS_MODE_32 | endian_mode(spec.arch_byte_order));
    break;
  case mode::ppc64:
    cfg.arch = CS_ARCH_PPC;
    cfg.mode = static_cast<cs_mode>(CS_MODE_64 | endian_mode(spec.arch_byte_order));
    break;
  case mode::sparc32:
    cfg.arch = CS_ARCH_SPARC;
    cfg.mode = static_cast<cs_mode>(CS_MODE_32 | endian_mode(spec.arch_byte_order));
    break;
  case mode::sparc64:
    cfg.arch = CS_ARCH_SPARC;
    cfg.mode = static_cast<cs_mode>(CS_MODE_V9 | endian_mode(spec.arch_byte_order));
    break;
  case mode::systemz:
    cfg.arch = CS_ARCH_SYSTEMZ;
    cfg.mode = endian_mode(spec.arch_byte_order);
    break;
  case mode::wasm32:
    cfg.arch = CS_ARCH_WASM;
    cfg.mode = static_cast<cs_mode>(CS_MODE_32 | endian_mode(spec.arch_byte_order));
    break;
  case mode::wasm64:
    cfg.arch = CS_ARCH_WASM;
    cfg.mode = static_cast<cs_mode>(CS_MODE_64 | endian_mode(spec.arch_byte_order));
    break;
  case mode::unknown:
    return error_result<capstone_config>(error_code::unsupported, "unknown architecture");
  }
  return ok_result(cfg);
}

result<keystone_config> keystone_config_for(const arch_spec& input) {
  arch_spec spec = normalize_spec(input);
  keystone_config cfg{};
  cfg.normalized = spec;

  if (spec.arch_family == family::x86 && spec.arch_byte_order == byte_order::big) {
    return error_result<keystone_config>(error_code::unsupported, "x86 does not support big endian");
  }

  switch (spec.arch_mode) {
  case mode::x86_32:
    cfg.arch = KS_ARCH_X86;
    cfg.mode = KS_MODE_32;
    break;
  case mode::x86_64:
    cfg.arch = KS_ARCH_X86;
    cfg.mode = KS_MODE_64;
    break;
  case mode::arm:
    cfg.arch = KS_ARCH_ARM;
    cfg.mode = static_cast<ks_mode>(KS_MODE_ARM | keystone_endian_mode(spec.arch_byte_order));
    break;
  case mode::thumb:
    cfg.arch = KS_ARCH_ARM;
    cfg.mode = static_cast<ks_mode>(KS_MODE_THUMB | keystone_endian_mode(spec.arch_byte_order));
    break;
  case mode::aarch64:
    cfg.arch = KS_ARCH_ARM64;
    cfg.mode = keystone_endian_mode(spec.arch_byte_order);
    break;
  case mode::riscv32:
    cfg.arch = KS_ARCH_RISCV;
    cfg.mode = static_cast<ks_mode>(KS_MODE_RISCV32 | keystone_endian_mode(spec.arch_byte_order));
    break;
  case mode::riscv64:
    cfg.arch = KS_ARCH_RISCV;
    cfg.mode = static_cast<ks_mode>(KS_MODE_RISCV64 | keystone_endian_mode(spec.arch_byte_order));
    break;
  case mode::mips32:
    cfg.arch = KS_ARCH_MIPS;
    cfg.mode = static_cast<ks_mode>(KS_MODE_MIPS32 | keystone_endian_mode(spec.arch_byte_order));
    break;
  case mode::mips64:
    cfg.arch = KS_ARCH_MIPS;
    cfg.mode = static_cast<ks_mode>(KS_MODE_MIPS64 | keystone_endian_mode(spec.arch_byte_order));
    break;
  default:
    return error_result<keystone_config>(error_code::unsupported, "unsupported architecture for assembly");
  }
  return ok_result(cfg);
}

void append_reg_name(csh handle, uint32_t reg_id, std::string& out) {
  if (reg_id == 0) {
    return;
  }
  const char* name = cs_reg_name(handle, reg_id);
  if (name) {
    out = name;
  }
}

void append_x86_operands(csh handle, const cs_x86& detail, instruction& inst) {
  inst.encoding_info.imm_offset = detail.encoding.imm_offset;
  inst.encoding_info.imm_size = detail.encoding.imm_size;
  inst.encoding_info.disp_offset = detail.encoding.disp_offset;
  inst.encoding_info.disp_size = detail.encoding.disp_size;
  inst.encoding_info.modrm_offset = detail.encoding.modrm_offset;

  inst.operand_details.reserve(detail.op_count);
  for (uint8_t i = 0; i < detail.op_count; ++i) {
    const auto& op = detail.operands[i];
    operand out;
    int type = static_cast<int>(op.type);
    switch (type) {
    case X86_OP_REG:
      out.kind = operand_kind::reg;
      out.reg_id = op.reg;
      append_reg_name(handle, op.reg, out.reg_name);
      break;
    case X86_OP_IMM:
      out.kind = operand_kind::imm;
      out.imm = op.imm;
      break;
    case X86_OP_MEM:
      out.kind = operand_kind::mem;
      out.mem_base = op.mem.base;
      out.mem_index = op.mem.index;
      out.mem_scale = op.mem.scale;
      out.mem_disp = op.mem.disp;
      out.is_pc_relative = (op.mem.base == X86_REG_RIP || op.mem.base == X86_REG_EIP);
      break;
    default:
      continue;
    }
    inst.operand_details.push_back(std::move(out));
  }
}

void append_arm_operands(csh handle, const cs_arm& detail, instruction& inst) {
  inst.operand_details.reserve(detail.op_count);
  for (uint8_t i = 0; i < detail.op_count; ++i) {
    const auto& op = detail.operands[i];
    operand out;
    int type = static_cast<int>(op.type);
    switch (type) {
    case ARM_OP_REG:
      out.kind = operand_kind::reg;
      out.reg_id = op.reg;
      append_reg_name(handle, op.reg, out.reg_name);
      break;
    case ARM_OP_IMM:
    case ARM_OP_CIMM:
    case ARM_OP_PIMM:
      out.kind = operand_kind::imm;
      out.imm = op.imm;
      break;
    case ARM_OP_FP:
      out.kind = operand_kind::imm;
      out.imm = static_cast<int64_t>(op.fp);
      break;
    case ARM_OP_MEM:
      out.kind = operand_kind::mem;
      out.mem_base = op.mem.base;
      out.mem_index = op.mem.index;
      out.mem_scale = op.mem.scale;
      out.mem_disp = op.mem.disp;
      out.is_pc_relative = (op.mem.base == ARM_REG_PC);
      break;
    default:
      continue;
    }
    inst.operand_details.push_back(std::move(out));
  }
}

void append_arm64_operands(csh handle, const cs_arm64& detail, instruction& inst) {
  inst.operand_details.reserve(detail.op_count);
  for (uint8_t i = 0; i < detail.op_count; ++i) {
    const auto& op = detail.operands[i];
    operand out;
    int type = static_cast<int>(op.type);
    switch (type) {
    case ARM64_OP_REG:
    case ARM64_OP_REG_MRS:
    case ARM64_OP_REG_MSR:
    case ARM64_OP_SYSREG:
      out.kind = operand_kind::reg;
      out.reg_id = op.reg;
      append_reg_name(handle, op.reg, out.reg_name);
      break;
    case ARM64_OP_MEM:
    case ARM64_OP_MEM_REG:
    case ARM64_OP_MEM_IMM:
      out.kind = operand_kind::mem;
      out.mem_base = op.mem.base;
      out.mem_index = op.mem.index;
      out.mem_disp = op.mem.disp;
      out.is_pc_relative = false;
      break;
    case ARM64_OP_IMM:
    case ARM64_OP_CIMM:
      out.kind = operand_kind::imm;
      out.imm = op.imm;
      break;
    case ARM64_OP_IMPLICIT_IMM_0:
    case ARM64_OP_IMM_RANGE:
    case ARM64_OP_SYSIMM:
    case ARM64_OP_PSTATEIMM0_15:
    case ARM64_OP_PSTATEIMM0_1:
    case ARM64_OP_EXACTFPIMM:
      out.kind = operand_kind::imm;
      out.imm = 0;
      break;
    case ARM64_OP_FP:
      out.kind = operand_kind::imm;
      out.imm = static_cast<int64_t>(op.fp);
      break;
    default:
      continue;
    }
    inst.operand_details.push_back(std::move(out));
  }
}

const cs_arm64& arm64_detail(const cs_detail& detail) {
#ifdef CAPSTONE_AARCH64_COMPAT_HEADER
  return detail.arm64;
#else
  return detail.aarch64;
#endif
}

} // namespace

struct disasm_context::backend {
  csh capstone = 0;
  arch_spec arch_value{};

  ~backend() {
    if (capstone) {
      cs_close(&capstone);
      capstone = 0;
    }
  }
};

struct asm_context::backend {
  ks_engine* keystone = nullptr;
  arch_spec arch_value{};

  ~backend() {
    if (keystone) {
      ks_close(keystone);
      keystone = nullptr;
    }
  }
};

disasm_context::~disasm_context() = default;
disasm_context::disasm_context(disasm_context&&) noexcept = default;
disasm_context& disasm_context::operator=(disasm_context&&) noexcept = default;

asm_context::~asm_context() = default;
asm_context::asm_context(asm_context&&) noexcept = default;
asm_context& asm_context::operator=(asm_context&&) noexcept = default;

disasm_context::disasm_context(const arch_spec& arch_value, std::unique_ptr<backend> backend)
    : backend_(std::move(backend)), arch_(arch_value) {}

asm_context::asm_context(const arch_spec& arch_value, std::unique_ptr<backend> backend)
    : backend_(std::move(backend)), arch_(arch_value) {}

result<disasm_context> disasm_context::for_arch(const arch_spec& spec) {
  auto caps = arch_capabilities_for(spec);
  if (!caps.disasm) {
    return error_result<disasm_context>(error_code::unsupported, "disassembly not supported for this architecture");
  }

  auto capstone_cfg = capstone_config_for(spec);
  if (!capstone_cfg.ok()) {
    return error_result<disasm_context>(capstone_cfg.status_info.code, capstone_cfg.status_info.message);
  }

  auto backend = std::make_unique<disasm_context::backend>();
  backend->arch_value = capstone_cfg.value.normalized;

  cs_err cs_status = cs_open(capstone_cfg.value.arch, capstone_cfg.value.mode, &backend->capstone);
  if (cs_status != CS_ERR_OK) {
    return error_result<disasm_context>(
        error_code::internal_error, std::string("capstone init failed: ") + cs_strerror(cs_status)
    );
  }

  cs_status = cs_option(backend->capstone, CS_OPT_DETAIL, CS_OPT_ON);
  if (cs_status != CS_ERR_OK) {
    return error_result<disasm_context>(
        error_code::internal_error, std::string("capstone option failed: ") + cs_strerror(cs_status)
    );
  }

  if (backend->arch_value.arch_family == family::x86) {
    cs_option(backend->capstone, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
  }

  arch_spec arch_value = backend->arch_value;
  return ok_result(disasm_context(arch_value, std::move(backend)));
}

result<disasm_context> disasm_context::for_host() {
  auto detected = detect_host_arch_spec();
  if (!detected.ok()) {
    return error_result<disasm_context>(detected.status_info.code, detected.status_info.message);
  }
  return for_arch(detected.value);
}

result<std::vector<instruction>> disasm_context::disassemble(
    std::span<const uint8_t> bytes,
    uint64_t address
) const {
  if (!backend_ || !backend_->capstone) {
    return error_result<std::vector<instruction>>(error_code::invalid_context, "asmr context not initialized");
  }

  if (bytes.empty()) {
    return error_result<std::vector<instruction>>(error_code::invalid_argument, "disassembly input is empty");
  }

  cs_insn* insn = nullptr;
  size_t count = cs_disasm(backend_->capstone, bytes.data(), bytes.size(), address, 0, &insn);
  if (count == 0 || !insn) {
    return error_result<std::vector<instruction>>(error_code::not_found, "no instructions decoded");
  }

  std::vector<instruction> output;
  output.reserve(count);
  for (size_t i = 0; i < count; ++i) {
    const auto& entry = insn[i];
    instruction inst;
    inst.address = entry.address;
    inst.bytes.assign(entry.bytes, entry.bytes + entry.size);
    inst.mnemonic = entry.mnemonic;
    inst.operands = entry.op_str;
    inst.id = entry.id;
    inst.is_branch_relative = cs_insn_group(backend_->capstone, &entry, CS_GRP_BRANCH_RELATIVE);

    if (entry.detail) {
      if (arch_.arch_family == family::x86) {
        append_x86_operands(backend_->capstone, entry.detail->x86, inst);
      } else if (arch_.arch_mode == mode::aarch64) {
        append_arm64_operands(backend_->capstone, arm64_detail(*entry.detail), inst);
      } else if (arch_.arch_mode == mode::arm || arch_.arch_mode == mode::thumb) {
        append_arm_operands(backend_->capstone, entry.detail->arm, inst);
      }
    }

    output.push_back(std::move(inst));
  }

  cs_free(insn, count);
  return ok_result(std::move(output));
}

result<asm_context> asm_context::for_arch(const arch_spec& spec) {
  auto caps = arch_capabilities_for(spec);
  if (!caps.assemble) {
    return error_result<asm_context>(error_code::unsupported, "assembly not supported for this architecture");
  }

  auto keystone_cfg = keystone_config_for(spec);
  if (!keystone_cfg.ok()) {
    return error_result<asm_context>(keystone_cfg.status_info.code, keystone_cfg.status_info.message);
  }
  if (!ks_arch_supported(keystone_cfg.value.arch)) {
    return error_result<asm_context>(
        error_code::unsupported, "keystone backend not built for requested architecture"
    );
  }

  auto backend = std::make_unique<asm_context::backend>();
  backend->arch_value = keystone_cfg.value.normalized;

  ks_err ks_status = ks_open(keystone_cfg.value.arch, keystone_cfg.value.mode, &backend->keystone);
  if (ks_status != KS_ERR_OK) {
    return error_result<asm_context>(
        error_code::internal_error, std::string("keystone init failed: ") + ks_strerror(ks_status)
    );
  }
  if (!backend->keystone) {
    return error_result<asm_context>(error_code::internal_error, "keystone returned null engine");
  }

  // Keystone defaults to Intel syntax on x86, so no explicit option is required here.

  arch_spec arch_value = backend->arch_value;
  return ok_result(asm_context(arch_value, std::move(backend)));
}

result<asm_context> asm_context::for_host() {
  auto detected = detect_host_arch_spec();
  if (!detected.ok()) {
    return error_result<asm_context>(detected.status_info.code, detected.status_info.message);
  }
  return for_arch(detected.value);
}

result<std::vector<uint8_t>> asm_context::assemble(std::string_view text, uint64_t address) const {
  if (!backend_ || !backend_->keystone) {
    return error_result<std::vector<uint8_t>>(error_code::invalid_context, "asmr context not initialized");
  }

  if (text.empty()) {
    return error_result<std::vector<uint8_t>>(error_code::invalid_argument, "assembly input is empty");
  }

  std::string input(text);
  unsigned char* encode = nullptr;
  size_t size = 0;
  size_t count = 0;

  int status = ks_asm(backend_->keystone, input.c_str(), address, &encode, &size, &count);
  if (status != 0) {
    ks_err ks_error = ks_errno(backend_->keystone);
    return error_result<std::vector<uint8_t>>(
        error_code::invalid_argument, std::string("keystone assemble failed: ") + ks_strerror(ks_error)
    );
  }

  std::vector<uint8_t> output;
  output.reserve(size);
  output.insert(output.end(), encode, encode + size);
  ks_free(encode);
  return ok_result(std::move(output));
}

} // namespace w1::asmr
