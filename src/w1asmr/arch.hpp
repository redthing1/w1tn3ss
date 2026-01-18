#pragma once

#include <string_view>

#include "w1asmr/result.hpp"

namespace w1::asmr {

enum class arch { x86, x64, arm64 };

std::string_view arch_to_string(arch value);
result<arch> parse_arch(std::string_view text);
result<arch> detect_host_arch();

} // namespace w1::asmr
