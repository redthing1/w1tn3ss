#pragma once

#include <string>
#include <vector>

#include "w1base/arch_spec.hpp"
#include "w1rewind/format/trace_format.hpp"

namespace w1::rewind {

struct register_spec_validation_options {
  bool allow_empty = false;
};

bool validate_trace_arch(const w1::arch::arch_spec& arch, std::string& error);
bool normalize_register_specs(
    std::vector<register_spec>& specs, std::string& error, register_spec_validation_options options = {}
);

} // namespace w1::rewind
