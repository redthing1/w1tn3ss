#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace w1::arch {

enum class family : uint16_t { unknown, x86, arm, riscv, mips, ppc, sparc, systemz, wasm };

enum class mode : uint16_t {
  unknown,
  x86_32,
  x86_64,
  arm,
  thumb,
  aarch64,
  riscv32,
  riscv64,
  mips32,
  mips64,
  ppc32,
  ppc64,
  sparc32,
  sparc64,
  systemz,
  wasm32,
  wasm64
};

enum class byte_order : uint8_t { unknown, little, big };

struct arch_spec {
  family arch_family = family::unknown;
  mode arch_mode = mode::unknown;
  byte_order arch_byte_order = byte_order::unknown;
  uint32_t pointer_bits = 0;
  uint32_t flags = 0;
};

inline constexpr bool operator==(const arch_spec& lhs, const arch_spec& rhs) noexcept {
  return lhs.arch_family == rhs.arch_family && lhs.arch_mode == rhs.arch_mode &&
         lhs.arch_byte_order == rhs.arch_byte_order && lhs.pointer_bits == rhs.pointer_bits && lhs.flags == rhs.flags;
}

inline constexpr bool operator!=(const arch_spec& lhs, const arch_spec& rhs) noexcept { return !(lhs == rhs); }

bool parse_arch_spec(std::string_view text, arch_spec& out, std::string& error);
arch_spec detect_host_arch_spec();
uint32_t default_pointer_bits(mode mode_value);
byte_order default_byte_order(family fam, mode mode_value);
std::string_view gdb_arch_name(const arch_spec& spec);
std::string_view gdb_feature_name(const arch_spec& spec);

} // namespace w1::arch
