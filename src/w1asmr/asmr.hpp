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

class context {
public:
  context() = default;
  ~context();
  context(context&&) noexcept = default;
  context& operator=(context&&) noexcept = default;
  context(const context&) = delete;
  context& operator=(const context&) = delete;

  static result<context> for_arch(arch arch_value);
  static result<context> for_host();

  result<std::vector<uint8_t>> assemble(std::string_view text, uint64_t address) const;
  result<std::vector<instruction>> disassemble(std::span<const uint8_t> bytes, uint64_t address) const;

  arch architecture() const noexcept { return arch_; }

private:
  struct backend;

  explicit context(arch arch_value, std::unique_ptr<backend> backend);

  std::unique_ptr<backend> backend_;
  arch arch_ = arch::x64;
};

} // namespace w1::asmr
