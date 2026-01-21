#include "trace_validator.hpp"

#include <algorithm>

namespace w1::rewind {

bool validate_trace_arch(const w1::arch::arch_spec& arch, std::string& error) {
  if (arch.arch_family == w1::arch::family::unknown || arch.arch_mode == w1::arch::mode::unknown) {
    error = "trace arch spec missing";
    return false;
  }
  if (arch.pointer_bits == 0 || (arch.pointer_bits % 8) != 0) {
    error = "trace pointer bits invalid";
    return false;
  }
  if (arch.arch_byte_order == w1::arch::byte_order::unknown) {
    error = "trace byte order missing";
    return false;
  }
  return true;
}

bool normalize_register_specs(
    std::vector<register_spec>& specs, std::string& error, register_spec_validation_options options
) {
  if (specs.empty()) {
    if (options.allow_empty) {
      return true;
    }
    error = "register specs missing";
    return false;
  }

  uint16_t max_id = 0;
  for (const auto& spec : specs) {
    if (spec.name.empty()) {
      error = "register spec name missing";
      return false;
    }
    if (spec.bits == 0) {
      error = "register spec bits missing";
      return false;
    }
    max_id = std::max(max_id, spec.reg_id);
  }

  size_t expected = static_cast<size_t>(max_id) + 1;
  if (expected != specs.size()) {
    error = "register ids must be contiguous";
    return false;
  }

  std::vector<register_spec> ordered(expected);
  std::vector<bool> seen(expected, false);
  for (auto& spec : specs) {
    if (spec.reg_id >= expected) {
      error = "register id out of range";
      return false;
    }
    if (seen[spec.reg_id]) {
      error = "duplicate register id";
      return false;
    }
    seen[spec.reg_id] = true;
    ordered[spec.reg_id] = std::move(spec);
  }
  specs = std::move(ordered);
  return true;
}

} // namespace w1::rewind
