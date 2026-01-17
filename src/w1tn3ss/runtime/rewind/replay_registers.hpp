#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "trace_format.hpp"

namespace w1::rewind {

inline std::optional<uint16_t> find_register_id(const std::vector<std::string>& names, const std::string& target) {
  for (size_t i = 0; i < names.size(); ++i) {
    if (names[i] == target) {
      return static_cast<uint16_t>(i);
    }
  }
  return std::nullopt;
}

inline std::optional<uint16_t> resolve_stack_reg_id(trace_arch arch, const std::vector<std::string>& names) {
  switch (arch) {
  case trace_arch::x86_64:
    return find_register_id(names, "rsp");
  case trace_arch::x86:
    return find_register_id(names, "esp");
  case trace_arch::aarch64:
  case trace_arch::arm:
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

} // namespace w1::rewind
