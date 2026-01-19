#include "w1base/arch_spec.hpp"

#include <cctype>
#include <string>

namespace w1::arch {

namespace {

std::string trim_lower(std::string_view input) {
  size_t start = 0;
  while (start < input.size() && std::isspace(static_cast<unsigned char>(input[start])) != 0) {
    ++start;
  }
  size_t end = input.size();
  while (end > start && std::isspace(static_cast<unsigned char>(input[end - 1])) != 0) {
    --end;
  }

  std::string output;
  output.reserve(end - start);
  for (size_t i = start; i < end; ++i) {
    output.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(input[i]))));
  }
  return output;
}

bool strip_suffix(std::string& value, std::string_view suffix) {
  if (value.size() < suffix.size()) {
    return false;
  }
  if (value.compare(value.size() - suffix.size(), suffix.size(), suffix) != 0) {
    return false;
  }
  value.erase(value.size() - suffix.size());
  return true;
}

byte_order detect_native_byte_order() {
  uint16_t value = 0x0102;
  auto* bytes = reinterpret_cast<const uint8_t*>(&value);
  if (bytes[0] == 0x02) {
    return byte_order::little;
  }
  if (bytes[0] == 0x01) {
    return byte_order::big;
  }
  return byte_order::unknown;
}

bool allow_override(byte_order order, family fam, mode mode_value, std::string& error) {
  if (order == byte_order::unknown) {
    return true;
  }
  if (fam == family::x86 || mode_value == mode::wasm32 || mode_value == mode::wasm64) {
    if (order == byte_order::big) {
      error = "big endian is not supported for this architecture";
      return false;
    }
  }
  if (fam == family::systemz) {
    if (order == byte_order::little) {
      error = "little endian is not supported for systemz";
      return false;
    }
  }
  return true;
}

} // namespace

uint32_t default_pointer_bits(mode mode_value) {
  switch (mode_value) {
  case mode::x86_32:
  case mode::arm:
  case mode::thumb:
  case mode::riscv32:
  case mode::mips32:
  case mode::ppc32:
  case mode::sparc32:
  case mode::wasm32:
    return 32;
  case mode::x86_64:
  case mode::aarch64:
  case mode::riscv64:
  case mode::mips64:
  case mode::ppc64:
  case mode::sparc64:
  case mode::systemz:
  case mode::wasm64:
    return 64;
  case mode::unknown:
    break;
  }
  return 0;
}

byte_order default_byte_order(family fam, mode mode_value) {
  switch (fam) {
  case family::x86:
  case family::arm:
  case family::riscv:
  case family::wasm:
    return byte_order::little;
  case family::mips:
  case family::ppc:
  case family::sparc:
  case family::systemz:
    return byte_order::big;
  case family::unknown:
    break;
  }

  if (mode_value == mode::systemz) {
    return byte_order::big;
  }
  return byte_order::unknown;
}

bool parse_arch_spec(std::string_view text, arch_spec& out, std::string& error) {
  error.clear();
  std::string value = trim_lower(text);
  if (value.empty()) {
    error = "architecture value is empty";
    return false;
  }

  byte_order override_order = byte_order::unknown;
  size_t colon = value.find(':');
  if (colon != std::string::npos) {
    std::string suffix = value.substr(colon + 1);
    value.resize(colon);
    if (suffix == "le" || suffix == "little") {
      override_order = byte_order::little;
    } else if (suffix == "be" || suffix == "big") {
      override_order = byte_order::big;
    } else {
      error = "unknown endianness override";
      return false;
    }
  }

  if (override_order == byte_order::unknown) {
    if (strip_suffix(value, "le")) {
      override_order = byte_order::little;
    } else if (strip_suffix(value, "be")) {
      override_order = byte_order::big;
    }
  }

  if (value.empty()) {
    error = "architecture value is empty";
    return false;
  }

  arch_spec spec{};
  if (value == "x86" || value == "i386" || value == "i486" || value == "i586" || value == "i686" ||
      value == "x86_32" || value == "x86-32") {
    spec.arch_family = family::x86;
    spec.arch_mode = mode::x86_32;
  } else if (value == "x64" || value == "x86_64" || value == "x86-64" || value == "amd64") {
    spec.arch_family = family::x86;
    spec.arch_mode = mode::x86_64;
  } else if (value == "arm" || value == "arm32" || value == "armv7" || value == "armv7l") {
    spec.arch_family = family::arm;
    spec.arch_mode = mode::arm;
  } else if (value == "thumb" || value == "thumb2") {
    spec.arch_family = family::arm;
    spec.arch_mode = mode::thumb;
  } else if (value == "arm64" || value == "aarch64") {
    spec.arch_family = family::arm;
    spec.arch_mode = mode::aarch64;
  } else if (value == "riscv32" || value == "rv32") {
    spec.arch_family = family::riscv;
    spec.arch_mode = mode::riscv32;
  } else if (value == "riscv64" || value == "rv64") {
    spec.arch_family = family::riscv;
    spec.arch_mode = mode::riscv64;
  } else if (value == "mips32" || value == "mips") {
    spec.arch_family = family::mips;
    spec.arch_mode = mode::mips32;
  } else if (value == "mips64") {
    spec.arch_family = family::mips;
    spec.arch_mode = mode::mips64;
  } else if (value == "ppc32" || value == "ppc" || value == "powerpc") {
    spec.arch_family = family::ppc;
    spec.arch_mode = mode::ppc32;
  } else if (value == "ppc64" || value == "powerpc64") {
    spec.arch_family = family::ppc;
    spec.arch_mode = mode::ppc64;
  } else if (value == "sparc32" || value == "sparc") {
    spec.arch_family = family::sparc;
    spec.arch_mode = mode::sparc32;
  } else if (value == "sparc64") {
    spec.arch_family = family::sparc;
    spec.arch_mode = mode::sparc64;
  } else if (value == "systemz" || value == "s390x" || value == "s390") {
    spec.arch_family = family::systemz;
    spec.arch_mode = mode::systemz;
  } else if (value == "wasm32") {
    spec.arch_family = family::wasm;
    spec.arch_mode = mode::wasm32;
  } else if (value == "wasm64") {
    spec.arch_family = family::wasm;
    spec.arch_mode = mode::wasm64;
  } else {
    error = "unsupported architecture: " + value;
    return false;
  }

  spec.pointer_bits = default_pointer_bits(spec.arch_mode);
  spec.arch_byte_order = default_byte_order(spec.arch_family, spec.arch_mode);
  if (!allow_override(override_order, spec.arch_family, spec.arch_mode, error)) {
    return false;
  }
  if (override_order != byte_order::unknown) {
    spec.arch_byte_order = override_order;
  }

  out = spec;
  return true;
}

arch_spec detect_host_arch_spec() {
  arch_spec spec{};
#if defined(__x86_64__) || defined(_M_X64)
  spec.arch_family = family::x86;
  spec.arch_mode = mode::x86_64;
#elif defined(__i386__) || defined(_M_IX86)
  spec.arch_family = family::x86;
  spec.arch_mode = mode::x86_32;
#elif defined(__aarch64__) || defined(_M_ARM64)
  spec.arch_family = family::arm;
  spec.arch_mode = mode::aarch64;
#elif defined(__arm__) || defined(_M_ARM)
  spec.arch_family = family::arm;
#if defined(__thumb__)
  spec.arch_mode = mode::thumb;
#else
  spec.arch_mode = mode::arm;
#endif
#else
  spec.arch_family = family::unknown;
  spec.arch_mode = mode::unknown;
#endif

  spec.pointer_bits = static_cast<uint32_t>(sizeof(void*) * 8);
  spec.arch_byte_order = detect_native_byte_order();
  if (spec.arch_byte_order == byte_order::unknown) {
    spec.arch_byte_order = default_byte_order(spec.arch_family, spec.arch_mode);
  }
  spec.flags = 0;
  return spec;
}

std::string_view gdb_arch_name(const arch_spec& spec) {
  switch (spec.arch_mode) {
  case mode::x86_64:
    return "i386:x86-64";
  case mode::x86_32:
    return "i386";
  case mode::aarch64:
    return "aarch64";
  case mode::arm:
  case mode::thumb:
    return "arm";
  default:
    break;
  }
  return {};
}

std::string_view gdb_feature_name(const arch_spec& spec) {
  switch (spec.arch_mode) {
  case mode::x86_64:
  case mode::x86_32:
    return "org.gnu.gdb.i386.core";
  case mode::aarch64:
    return "org.gnu.gdb.aarch64.core";
  case mode::arm:
  case mode::thumb:
    return "org.gnu.gdb.arm.core";
  default:
    break;
  }
  return "org.w1tn3ss.rewind";
}

} // namespace w1::arch
