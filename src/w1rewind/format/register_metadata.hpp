#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "w1base/arch_spec.hpp"
#include "w1rewind/format/register_numbering.hpp"
#include "w1rewind/format/trace_format.hpp"

namespace w1::rewind {

inline bool is_pc_name(std::string_view name) { return name == "pc" || name == "rip" || name == "eip"; }

inline bool is_sp_name(std::string_view name) { return name == "sp" || name == "rsp" || name == "esp"; }

inline bool is_flags_name(std::string_view name) {
  return name == "eflags" || name == "rflags" || name == "nzcv" || name == "cpsr";
}

inline uint16_t register_flags_for_name(std::string_view name) {
  uint16_t flags = 0;
  if (is_pc_name(name)) {
    flags |= register_flag_pc;
  }
  if (is_sp_name(name)) {
    flags |= register_flag_sp;
  }
  if (is_flags_name(name)) {
    flags |= register_flag_flags;
  }
  return flags;
}

inline register_class register_class_for_name(std::string_view name) {
  if (is_flags_name(name)) {
    return register_class::flags;
  }
  return register_class::gpr;
}

inline register_value_kind register_value_kind_for_name(std::string_view name) {
  (void) name;
  return register_value_kind::u64;
}

inline uint32_t register_bitsize(const w1::arch::arch_spec& arch, std::string_view name, uint32_t pointer_size_bytes) {
  uint32_t pointer_bits = pointer_size_bytes * 8;
  if (arch.arch_mode == w1::arch::mode::x86_64 || arch.arch_mode == w1::arch::mode::x86_32) {
    if (name == "eflags" || name == "rflags") {
      return 32;
    }
    if (name == "fs" || name == "gs") {
      return 16;
    }
  }
  if (arch.arch_mode == w1::arch::mode::aarch64) {
    if (name == "nzcv") {
      return 32;
    }
  }
  if (arch.arch_mode == w1::arch::mode::arm || arch.arch_mode == w1::arch::mode::thumb) {
    if (name == "cpsr") {
      return 32;
    }
  }
  return pointer_bits;
}

inline std::string gdb_name_for_register(std::string_view name, const w1::arch::arch_spec& arch) {
  if (arch.arch_mode == w1::arch::mode::aarch64 && name == "nzcv") {
    return "cpsr";
  }
  if (name == "rflags") {
    return "eflags";
  }
  return std::string(name);
}

inline std::optional<uint16_t> find_register_id(const std::vector<std::string>& names, std::string_view target) {
  for (size_t i = 0; i < names.size(); ++i) {
    if (names[i] == target) {
      return static_cast<uint16_t>(i);
    }
  }
  return std::nullopt;
}

inline std::optional<uint16_t> resolve_sp_reg_id(
    const w1::arch::arch_spec& arch, const std::vector<std::string>& names
) {
  switch (arch.arch_mode) {
  case w1::arch::mode::x86_64:
    return find_register_id(names, "rsp");
  case w1::arch::mode::x86_32:
    return find_register_id(names, "esp");
  case w1::arch::mode::aarch64:
  case w1::arch::mode::arm:
  case w1::arch::mode::thumb:
    return find_register_id(names, "sp");
  default:
    break;
  }
  auto candidate = find_register_id(names, "sp");
  if (candidate.has_value()) {
    return candidate;
  }
  candidate = find_register_id(names, "rsp");
  if (candidate.has_value()) {
    return candidate;
  }
  return find_register_id(names, "esp");
}

inline std::optional<uint16_t> resolve_pc_reg_id(
    const w1::arch::arch_spec& arch, const std::vector<std::string>& names
) {
  switch (arch.arch_mode) {
  case w1::arch::mode::x86_64:
    return find_register_id(names, "rip");
  case w1::arch::mode::x86_32:
    return find_register_id(names, "eip");
  case w1::arch::mode::aarch64:
  case w1::arch::mode::arm:
  case w1::arch::mode::thumb:
    return find_register_id(names, "pc");
  default:
    break;
  }
  auto candidate = find_register_id(names, "pc");
  if (candidate.has_value()) {
    return candidate;
  }
  candidate = find_register_id(names, "rip");
  if (candidate.has_value()) {
    return candidate;
  }
  return find_register_id(names, "eip");
}

inline register_spec build_register_spec(
    const w1::arch::arch_spec& arch, uint16_t reg_id, std::string_view name, uint32_t pointer_size_bytes
) {
  register_spec spec{};
  spec.reg_id = reg_id;
  spec.name = std::string(name);
  spec.bits = static_cast<uint16_t>(register_bitsize(arch, spec.name, pointer_size_bytes));
  spec.flags = register_flags_for_name(spec.name);
  spec.gdb_name = gdb_name_for_register(spec.name, arch);
  spec.reg_class = register_class_for_name(spec.name);
  spec.value_kind = register_value_kind_for_name(spec.name);
  if (auto numbering = lookup_register_numbering(arch, spec.gdb_name)) {
    spec.dwarf_regnum = numbering->dwarf_regnum;
    spec.ehframe_regnum = numbering->ehframe_regnum;
  }
  return spec;
}

} // namespace w1::rewind
