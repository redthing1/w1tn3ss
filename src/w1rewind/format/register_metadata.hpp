#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "w1rewind/format/trace_format.hpp"

namespace w1::rewind {

inline bool is_pc_name(std::string_view name) { return name == "pc" || name == "rip" || name == "eip"; }

inline bool is_sp_name(std::string_view name) { return name == "sp" || name == "rsp" || name == "esp"; }

inline bool is_flags_name(std::string_view name) {
  return name == "eflags" || name == "rflags" || name == "nzcv" || name == "cpsr";
}

inline uint32_t register_byte_size(const register_spec& spec) {
  return spec.bit_size == 0 ? 0u : static_cast<uint32_t>((spec.bit_size + 7u) / 8u);
}

inline std::optional<uint32_t> find_register_id_by_name(
    const std::vector<register_spec>& specs, std::string_view target
) {
  for (const auto& spec : specs) {
    if (spec.name == target || (!spec.gdb_name.empty() && spec.gdb_name == target)) {
      return spec.reg_id;
    }
  }
  return std::nullopt;
}

inline std::optional<uint32_t> resolve_sp_reg_id(const std::vector<register_spec>& specs) {
  for (const auto& spec : specs) {
    if ((spec.flags & register_flag_sp) != 0) {
      return spec.reg_id;
    }
  }
  return std::nullopt;
}

inline std::optional<uint32_t> resolve_pc_reg_id(const std::vector<register_spec>& specs) {
  for (const auto& spec : specs) {
    if ((spec.flags & register_flag_pc) != 0) {
      return spec.reg_id;
    }
  }
  return std::nullopt;
}

} // namespace w1::rewind
