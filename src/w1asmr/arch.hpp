#pragma once

#include <string_view>

#include "w1asmr/result.hpp"
#include "w1base/arch_spec.hpp"

namespace w1::asmr {

using w1::arch::arch_spec;
using w1::arch::byte_order;
using w1::arch::family;
using w1::arch::mode;

result<arch_spec> parse_arch_spec(std::string_view text);
result<arch_spec> detect_host_arch_spec();

struct arch_capabilities {
  bool disasm = false;
  bool assemble = false;
};

arch_capabilities arch_capabilities_for(const arch_spec& spec);

} // namespace w1::asmr
