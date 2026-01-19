#include "w1asmr/arch.hpp"

#include <string>

namespace w1::asmr {

result<arch_spec> parse_arch_spec(std::string_view text) {
  arch_spec spec{};
  std::string error;
  if (!w1::arch::parse_arch_spec(text, spec, error)) {
    auto code = error_code::invalid_argument;
    if (error.find("unsupported architecture") != std::string::npos) {
      code = error_code::unsupported;
    }
    return error_result<arch_spec>(code, std::move(error));
  }
  return ok_result(spec);
}

result<arch_spec> detect_host_arch_spec() {
  arch_spec spec = w1::arch::detect_host_arch_spec();
  if (spec.arch_mode == mode::unknown) {
    return error_result<arch_spec>(error_code::unsupported, "unsupported host architecture");
  }
  return ok_result(spec);
}

arch_capabilities arch_capabilities_for(const arch_spec& spec) {
  if (spec.arch_mode == mode::unknown) {
    return {};
  }

  arch_capabilities caps{};
  caps.disasm = true;

  switch (spec.arch_mode) {
  case mode::x86_32:
  case mode::x86_64:
  case mode::aarch64:
  case mode::arm:
  case mode::thumb:
  case mode::riscv32:
  case mode::riscv64:
  case mode::mips32:
  case mode::mips64:
    caps.assemble = true;
    break;
  default:
    caps.assemble = false;
    break;
  }
  return caps;
}

} // namespace w1::asmr
