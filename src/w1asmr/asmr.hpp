#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "w1asmr/arch.hpp"
#include "w1asmr/result.hpp"

namespace w1::asmr {

enum class operand_kind { reg, imm, mem };

struct encoding {
  uint8_t imm_offset = 0;
  uint8_t imm_size = 0;
  uint8_t disp_offset = 0;
  uint8_t disp_size = 0;
  uint8_t modrm_offset = 0;
};

struct operand {
  operand_kind kind = operand_kind::reg;
  uint32_t reg_id = 0;
  std::string reg_name;
  int64_t imm = 0;
  uint32_t mem_base = 0;
  uint32_t mem_index = 0;
  int32_t mem_scale = 0;
  int64_t mem_disp = 0;
  bool is_pc_relative = false;
};

struct instruction {
  uint64_t address = 0;
  std::vector<uint8_t> bytes;
  std::string mnemonic;
  std::string operands;
  uint32_t id = 0;
  std::vector<operand> operand_details;
  encoding encoding_info;
  bool is_branch_relative = false;
};

class disasm_context {
public:
  disasm_context() = default;
  ~disasm_context();
  disasm_context(disasm_context&&) noexcept;
  disasm_context& operator=(disasm_context&&) noexcept;
  disasm_context(const disasm_context&) = delete;
  disasm_context& operator=(const disasm_context&) = delete;

  static result<disasm_context> for_arch(const arch_spec& spec);
  static result<disasm_context> for_host();

  result<std::vector<instruction>> disassemble(std::span<const uint8_t> bytes, uint64_t address) const;

  const arch_spec& architecture() const noexcept { return arch_; }

private:
  struct backend;

  explicit disasm_context(const arch_spec& arch_value, std::unique_ptr<backend> backend);

  std::unique_ptr<backend> backend_;
  arch_spec arch_{};
};

class asm_context {
public:
  asm_context() = default;
  ~asm_context();
  asm_context(asm_context&&) noexcept;
  asm_context& operator=(asm_context&&) noexcept;
  asm_context(const asm_context&) = delete;
  asm_context& operator=(const asm_context&) = delete;

  static result<asm_context> for_arch(const arch_spec& spec);
  static result<asm_context> for_host();

  result<std::vector<uint8_t>> assemble(std::string_view text, uint64_t address) const;

  const arch_spec& architecture() const noexcept { return arch_; }

private:
  struct backend;

  explicit asm_context(const arch_spec& arch_value, std::unique_ptr<backend> backend);

  std::unique_ptr<backend> backend_;
  arch_spec arch_{};
};

} // namespace w1::asmr
