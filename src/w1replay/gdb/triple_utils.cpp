#include "triple_utils.hpp"

#include <algorithm>

namespace w1replay::gdb {

namespace {

std::string lower_ascii(std::string_view value) {
  std::string out(value);
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return out;
}

std::string triple_arch_from_descriptor(const w1::rewind::arch_descriptor_record& arch) {
  if (arch.arch_id.empty()) {
    return {};
  }
  std::string id = lower_ascii(arch.arch_id);
  if (id == "x86_64" || id == "amd64") {
    return "x86_64";
  }
  if (id == "x86" || id == "i386" || id == "x86_32") {
    return "i386";
  }
  if (id == "aarch64" || id == "arm64") {
    return "aarch64";
  }
  if (id == "arm" || id == "thumb" || id == "armv7") {
    return "arm";
  }
  if (id == "riscv64") {
    return "riscv64";
  }
  if (id == "riscv32") {
    return "riscv32";
  }
  if (id == "mips64") {
    return "mips64";
  }
  if (id == "mips" || id == "mips32") {
    return "mips";
  }
  if (id == "ppc64" || id == "powerpc64") {
    return "powerpc64";
  }
  if (id == "ppc" || id == "powerpc") {
    return "powerpc";
  }
  if (id == "sparc64") {
    return "sparcv9";
  }
  if (id == "sparc") {
    return "sparc";
  }
  if (id == "systemz" || id == "s390x") {
    return "s390x";
  }
  if (id == "wasm32") {
    return "wasm32";
  }
  if (id == "wasm64") {
    return "wasm64";
  }

  return id;
}

} // namespace

std::string build_process_triple(
    const w1::rewind::arch_descriptor_record& arch, const std::string& os_id, const std::string& abi
) {
  std::string arch_part = triple_arch_from_descriptor(arch);
  if (arch_part.empty()) {
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

  std::string triple = arch_part + "-" + vendor + "-" + os;
  if (!env.empty()) {
    triple += "-";
    triple += env;
  }
  return triple;
}

} // namespace w1replay::gdb
