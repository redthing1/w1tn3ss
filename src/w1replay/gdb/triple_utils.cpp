#include "triple_utils.hpp"

namespace w1replay::gdb {

namespace {
std::string triple_arch_from_spec(const w1::arch::arch_spec& spec) {
  using w1::arch::family;
  using w1::arch::mode;
  switch (spec.arch_mode) {
  case mode::x86_64:
    return "x86_64";
  case mode::x86_32:
    return "i386";
  case mode::arm:
    return "arm";
  case mode::thumb:
    return "thumb";
  case mode::aarch64:
    return "aarch64";
  case mode::riscv32:
    return "riscv32";
  case mode::riscv64:
    return "riscv64";
  case mode::mips32:
    return "mips";
  case mode::mips64:
    return "mips64";
  case mode::ppc32:
    return "powerpc";
  case mode::ppc64:
    return "powerpc64";
  case mode::sparc32:
    return "sparc";
  case mode::sparc64:
    return "sparcv9";
  case mode::systemz:
    return "s390x";
  case mode::wasm32:
    return "wasm32";
  case mode::wasm64:
    return "wasm64";
  default:
    break;
  }

  switch (spec.arch_family) {
  case family::x86:
    return spec.pointer_bits == 64 ? "x86_64" : "i386";
  case family::arm:
    return spec.pointer_bits == 64 ? "aarch64" : "arm";
  case family::riscv:
    return spec.pointer_bits == 64 ? "riscv64" : "riscv32";
  case family::mips:
    return spec.pointer_bits == 64 ? "mips64" : "mips";
  case family::ppc:
    return spec.pointer_bits == 64 ? "powerpc64" : "powerpc";
  case family::sparc:
    return spec.pointer_bits == 64 ? "sparcv9" : "sparc";
  case family::systemz:
    return "s390x";
  case family::wasm:
    return spec.pointer_bits == 64 ? "wasm64" : "wasm32";
  default:
    break;
  }

  return {};
}
} // namespace

std::string build_process_triple(const w1::arch::arch_spec& spec, const std::string& os_id, const std::string& abi) {
  std::string arch = triple_arch_from_spec(spec);
  if (arch.empty()) {
    return {};
  }

  std::string vendor = "unknown";
  std::string os = "unknown";
  std::string env;
  if (os_id == "linux") {
    os = "linux";
    env = abi.empty() ? "gnu" : abi;
  } else if (os_id == "macos") {
    vendor = "apple";
    os = "macosx";
    env = abi;
  } else if (os_id == "windows") {
    vendor = "pc";
    os = "windows";
    env = abi.empty() ? "msvc" : abi;
  } else if (!os_id.empty()) {
    os = os_id;
    env = abi;
  }

  std::string triple = arch + "-" + vendor + "-" + os;
  if (!env.empty()) {
    triple += "-";
    triple += env;
  }
  return triple;
}

} // namespace w1replay::gdb
