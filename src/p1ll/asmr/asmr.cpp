#include "asmr.hpp"

#include <capstone/arm64.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <keystone/keystone.h>

#include <algorithm>
#include <cctype>
#include <memory>
#include <string>
#include <utility>

namespace p1ll::asmr {

namespace {

struct capstone_config {
  cs_arch arch = CS_ARCH_X86;
  cs_mode mode = CS_MODE_64;
};

struct keystone_config {
  ks_arch arch = KS_ARCH_X86;
  ks_mode mode = KS_MODE_64;
};

engine::result<arch> parse_arch(const engine::platform::platform_key& platform) {
  if (platform.arch == "x86") {
    return engine::ok_result(arch::x86);
  }
  if (platform.arch == "x64") {
    return engine::ok_result(arch::x64);
  }
  if (platform.arch == "arm64") {
    return engine::ok_result(arch::arm64);
  }
  return engine::error_result<arch>(engine::error_code::unsupported, "unsupported architecture: " + platform.arch);
}

engine::result<capstone_config> capstone_config_for(arch arch_value) {
  capstone_config cfg;
  switch (arch_value) {
  case arch::x86:
    cfg.arch = CS_ARCH_X86;
    cfg.mode = CS_MODE_32;
    break;
  case arch::x64:
    cfg.arch = CS_ARCH_X86;
    cfg.mode = CS_MODE_64;
    break;
  case arch::arm64:
#ifdef CAPSTONE_AARCH64_COMPAT_HEADER
    cfg.arch = CS_ARCH_ARM64;
#else
    cfg.arch = CS_ARCH_AARCH64;
#endif
    cfg.mode = CS_MODE_LITTLE_ENDIAN;
    break;
  }
  return engine::ok_result(cfg);
}

engine::result<keystone_config> keystone_config_for(arch arch_value) {
  keystone_config cfg;
  switch (arch_value) {
  case arch::x86:
    cfg.arch = KS_ARCH_X86;
    cfg.mode = KS_MODE_32;
    break;
  case arch::x64:
    cfg.arch = KS_ARCH_X86;
    cfg.mode = KS_MODE_64;
    break;
  case arch::arm64:
    cfg.arch = KS_ARCH_ARM64;
    cfg.mode = KS_MODE_LITTLE_ENDIAN;
    break;
  }
  return engine::ok_result(cfg);
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
  inst.encoding.imm_offset = detail.encoding.imm_offset;
  inst.encoding.imm_size = detail.encoding.imm_size;
  inst.encoding.disp_offset = detail.encoding.disp_offset;
  inst.encoding.disp_size = detail.encoding.disp_size;
  inst.encoding.modrm_offset = detail.encoding.modrm_offset;

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

struct context::backend {
  csh capstone = 0;
  ks_engine* keystone = nullptr;
  arch arch_value = arch::x64;

  ~backend() {
    if (keystone) {
      ks_close(keystone);
      keystone = nullptr;
    }
    if (capstone) {
      cs_close(&capstone);
      capstone = 0;
    }
  }
};

context::~context() = default;

context::context(arch arch_value, std::unique_ptr<backend> backend) : backend_(std::move(backend)), arch_(arch_value) {}

engine::result<context> context::for_platform(const engine::platform::platform_key& platform) {
  auto parsed = parse_arch(platform);
  if (!parsed.ok()) {
    return engine::error_result<context>(parsed.status.code, parsed.status.message);
  }

  auto capstone_cfg = capstone_config_for(parsed.value);
  auto keystone_cfg = keystone_config_for(parsed.value);

  auto backend = std::make_unique<context::backend>();
  backend->arch_value = parsed.value;

  cs_err cs_status = cs_open(capstone_cfg.value.arch, capstone_cfg.value.mode, &backend->capstone);
  if (cs_status != CS_ERR_OK) {
    return engine::error_result<context>(
        engine::error_code::internal_error, std::string("capstone init failed: ") + cs_strerror(cs_status)
    );
  }

  cs_status = cs_option(backend->capstone, CS_OPT_DETAIL, CS_OPT_ON);
  if (cs_status != CS_ERR_OK) {
    return engine::error_result<context>(
        engine::error_code::internal_error, std::string("capstone option failed: ") + cs_strerror(cs_status)
    );
  }

  if (parsed.value == arch::x86 || parsed.value == arch::x64) {
    cs_option(backend->capstone, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
  }

  ks_err ks_status = ks_open(keystone_cfg.value.arch, keystone_cfg.value.mode, &backend->keystone);
  if (ks_status != KS_ERR_OK) {
    return engine::error_result<context>(
        engine::error_code::internal_error, std::string("keystone init failed: ") + ks_strerror(ks_status)
    );
  }

  if (parsed.value == arch::x86 || parsed.value == arch::x64) {
    ks_option(backend->keystone, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);
  }

  return engine::ok_result(context(parsed.value, std::move(backend)));
}

engine::result<context> context::for_host() { return for_platform(engine::platform::detect_platform()); }

engine::result<std::vector<uint8_t>> context::assemble(std::string_view text, uint64_t address) const {
  if (!backend_ || !backend_->keystone) {
    return engine::error_result<std::vector<uint8_t>>(
        engine::error_code::invalid_context, "asmr context not initialized"
    );
  }

  if (text.empty()) {
    return engine::error_result<std::vector<uint8_t>>(engine::error_code::invalid_argument, "assembly input is empty");
  }

  std::string input(text);
  unsigned char* encode = nullptr;
  size_t size = 0;
  size_t count = 0;

  int status = ks_asm(backend_->keystone, input.c_str(), address, &encode, &size, &count);
  if (status != 0) {
    ks_err error_code = ks_errno(backend_->keystone);
    return engine::error_result<std::vector<uint8_t>>(
        engine::error_code::invalid_argument, std::string("keystone assemble failed: ") + ks_strerror(error_code)
    );
  }

  std::vector<uint8_t> output;
  output.reserve(size);
  output.insert(output.end(), encode, encode + size);
  ks_free(encode);
  return engine::ok_result(std::move(output));
}

engine::result<std::vector<instruction>> context::disassemble(std::span<const uint8_t> bytes, uint64_t address) const {
  if (!backend_ || !backend_->capstone) {
    return engine::error_result<std::vector<instruction>>(
        engine::error_code::invalid_context, "asmr context not initialized"
    );
  }

  if (bytes.empty()) {
    return engine::error_result<std::vector<instruction>>(
        engine::error_code::invalid_argument, "disassembly input is empty"
    );
  }

  cs_insn* insn = nullptr;
  size_t count = cs_disasm(backend_->capstone, bytes.data(), bytes.size(), address, 0, &insn);
  if (count == 0 || !insn) {
    return engine::error_result<std::vector<instruction>>(engine::error_code::not_found, "no instructions decoded");
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
      if (arch_ == arch::x86 || arch_ == arch::x64) {
        append_x86_operands(backend_->capstone, entry.detail->x86, inst);
      } else if (arch_ == arch::arm64) {
        append_arm64_operands(backend_->capstone, arm64_detail(*entry.detail), inst);
      }
    }

    output.push_back(std::move(inst));
  }

  cs_free(insn, count);
  return engine::ok_result(std::move(output));
}

} // namespace p1ll::asmr
