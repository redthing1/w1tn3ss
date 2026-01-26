#include "qbdi_register_schema_provider.hpp"

#include <algorithm>
#include <cctype>
#include <optional>
#include <string>
#include <string_view>

#include <QBDI.h>

namespace {

using w1::rewind::arch_descriptor_record;
using w1::rewind::register_spec;
using w1::rewind::k_register_regnum_unknown;
using w1::rewind::register_flag_flags;
using w1::rewind::register_flag_fp;
using w1::rewind::register_flag_pc;
using w1::rewind::register_flag_sp;

std::string lower_ascii(std::string_view value) {
  std::string out(value);
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
  return out;
}

bool matches_any(std::string_view value, std::initializer_list<std::string_view> candidates) {
  for (auto candidate : candidates) {
    if (value == candidate) {
      return true;
    }
  }
  return false;
}

bool ensure_arch_compatible(
    const arch_descriptor_record& arch, std::initializer_list<std::string_view> arch_ids,
    std::initializer_list<std::string_view> gdb_arches, uint16_t pointer_bits, std::string& error
) {
  const std::string arch_id = lower_ascii(arch.arch_id);
  const std::string gdb_arch = lower_ascii(arch.gdb_arch);

  if (!arch_id.empty() && !matches_any(arch_id, arch_ids)) {
    error = "arch_id mismatch for QBDI register schema";
    return false;
  }
  if (!gdb_arch.empty() && !matches_any(gdb_arch, gdb_arches)) {
    error = "gdb_arch mismatch for QBDI register schema";
    return false;
  }
  if (pointer_bits != 0 && arch.pointer_bits != 0 && arch.pointer_bits != pointer_bits) {
    error = "pointer_bits mismatch for QBDI register schema";
    return false;
  }
  if (pointer_bits != 0 && arch.address_bits != 0 && arch.address_bits != pointer_bits) {
    error = "address_bits mismatch for QBDI register schema";
    return false;
  }
  return true;
}

void assign_reg_ids(std::vector<register_spec>& specs) {
  for (size_t i = 0; i < specs.size(); ++i) {
    specs[i].reg_id = static_cast<uint32_t>(i);
  }
}

void add_spec(
    std::vector<register_spec>& specs, std::string_view name, uint16_t bit_size, uint16_t flags = 0,
    std::string_view gdb_name = {}, uint32_t dwarf_regnum = k_register_regnum_unknown,
    uint32_t gcc_regnum = k_register_regnum_unknown
) {
  register_spec spec{};
  spec.name = std::string(name);
  spec.bit_size = bit_size;
  spec.flags = flags;
  if (!gdb_name.empty()) {
    spec.gdb_name = std::string(gdb_name);
  }
  spec.dwarf_regnum = dwarf_regnum;
  spec.gcc_regnum = gcc_regnum;
  specs.push_back(std::move(spec));
}

std::optional<uint32_t> parse_x_register(std::string_view name) {
  if (name.size() < 2 || name[0] != 'x') {
    return std::nullopt;
  }
  uint32_t value = 0;
  for (size_t i = 1; i < name.size(); ++i) {
    char c = name[i];
    if (c < '0' || c > '9') {
      return std::nullopt;
    }
    value = value * 10 + static_cast<uint32_t>(c - '0');
  }
  return value;
}

std::optional<uint32_t> dwarf_regnum_for_aarch64(std::string_view name) {
  if (name == "sp") {
    return 31u;
  }
  if (name == "pc") {
    return 32u;
  }
  if (name == "cpsr" || name == "nzcv") {
    return 33u;
  }
  if (name == "lr") {
    return 30u;
  }
  if (auto reg = parse_x_register(name)) {
    if (*reg <= 30u) {
      return *reg;
    }
  }
  return std::nullopt;
}

std::optional<uint32_t> dwarf_regnum_for_x86_64(std::string_view name) {
  if (name == "rax") {
    return 0u;
  }
  if (name == "rdx") {
    return 1u;
  }
  if (name == "rcx") {
    return 2u;
  }
  if (name == "rbx") {
    return 3u;
  }
  if (name == "rsi") {
    return 4u;
  }
  if (name == "rdi") {
    return 5u;
  }
  if (name == "rbp") {
    return 6u;
  }
  if (name == "rsp") {
    return 7u;
  }
  if (name == "r8") {
    return 8u;
  }
  if (name == "r9") {
    return 9u;
  }
  if (name == "r10") {
    return 10u;
  }
  if (name == "r11") {
    return 11u;
  }
  if (name == "r12") {
    return 12u;
  }
  if (name == "r13") {
    return 13u;
  }
  if (name == "r14") {
    return 14u;
  }
  if (name == "r15") {
    return 15u;
  }
  if (name == "rip") {
    return 16u;
  }
  if (name == "eflags") {
    return 49u;
  }
  return std::nullopt;
}

void apply_regnums(std::vector<register_spec>& specs, bool aarch64, bool x86_64) {
  for (auto& spec : specs) {
    if (spec.dwarf_regnum != k_register_regnum_unknown || spec.gcc_regnum != k_register_regnum_unknown) {
      continue;
    }
    std::string_view name = spec.gdb_name.empty() ? spec.name : spec.gdb_name;
    std::optional<uint32_t> regnum;
    if (aarch64) {
      regnum = dwarf_regnum_for_aarch64(name);
    } else if (x86_64) {
      regnum = dwarf_regnum_for_x86_64(name);
    }
    if (regnum.has_value()) {
      spec.dwarf_regnum = *regnum;
      spec.gcc_regnum = *regnum;
    }
  }
}

} // namespace

namespace w1rewind {

bool qbdi_register_schema_provider::build_register_schema(
    const w1::rewind::arch_descriptor_record& arch, std::vector<w1::rewind::register_spec>& out,
    std::string& error
) const {
  out.clear();
  error.clear();

#if defined(QBDI_ARCH_X86_64)
  if (!ensure_arch_compatible(arch, {"x86_64", "amd64"}, {"i386:x86-64"}, 64, error)) {
    return false;
  }
  add_spec(out, "rax", 64);
  add_spec(out, "rbx", 64);
  add_spec(out, "rcx", 64);
  add_spec(out, "rdx", 64);
  add_spec(out, "rsi", 64);
  add_spec(out, "rdi", 64);
  add_spec(out, "r8", 64);
  add_spec(out, "r9", 64);
  add_spec(out, "r10", 64);
  add_spec(out, "r11", 64);
  add_spec(out, "r12", 64);
  add_spec(out, "r13", 64);
  add_spec(out, "r14", 64);
  add_spec(out, "r15", 64);
  add_spec(out, "rbp", 64, register_flag_fp);
  add_spec(out, "rsp", 64, register_flag_sp);
  add_spec(out, "rip", 64, register_flag_pc);
  add_spec(out, "eflags", 32, register_flag_flags);
  add_spec(out, "fs", 16);
  add_spec(out, "gs", 16);
  apply_regnums(out, false, true);
#elif defined(QBDI_ARCH_X86)
  if (!ensure_arch_compatible(arch, {"x86", "i386", "x86_32"}, {"i386"}, 32, error)) {
    return false;
  }
  add_spec(out, "eax", 32);
  add_spec(out, "ebx", 32);
  add_spec(out, "ecx", 32);
  add_spec(out, "edx", 32);
  add_spec(out, "esi", 32);
  add_spec(out, "edi", 32);
  add_spec(out, "ebp", 32, register_flag_fp);
  add_spec(out, "esp", 32, register_flag_sp);
  add_spec(out, "eip", 32, register_flag_pc);
  add_spec(out, "eflags", 32, register_flag_flags);
#elif defined(QBDI_ARCH_AARCH64)
  if (!ensure_arch_compatible(arch, {"aarch64", "arm64"}, {"aarch64"}, 64, error)) {
    return false;
  }
  for (int i = 0; i < 29; ++i) {
    add_spec(out, "x" + std::to_string(i), 64);
  }
  add_spec(out, "x29", 64, register_flag_fp, "x29");
  add_spec(out, "lr", 64, 0, "x30");
  add_spec(out, "sp", 64, register_flag_sp);
  add_spec(out, "pc", 64, register_flag_pc);
  add_spec(out, "nzcv", 32, register_flag_flags, "cpsr");
  apply_regnums(out, true, false);
#elif defined(QBDI_ARCH_ARM)
  if (!ensure_arch_compatible(arch, {"arm", "thumb", "armv7"}, {"arm"}, 32, error)) {
    return false;
  }
  add_spec(out, "r0", 32);
  add_spec(out, "r1", 32);
  add_spec(out, "r2", 32);
  add_spec(out, "r3", 32);
  add_spec(out, "r4", 32);
  add_spec(out, "r5", 32);
  add_spec(out, "r6", 32);
  add_spec(out, "r7", 32);
  add_spec(out, "r8", 32);
  add_spec(out, "r9", 32);
  add_spec(out, "r10", 32);
  add_spec(out, "r11", 32, register_flag_fp);
  add_spec(out, "r12", 32);
  add_spec(out, "sp", 32, register_flag_sp);
  add_spec(out, "lr", 32);
  add_spec(out, "pc", 32, register_flag_pc);
  add_spec(out, "cpsr", 32, register_flag_flags);
#else
  error = "unsupported QBDI architecture for register schema";
  return false;
#endif

  if (out.empty()) {
    error = "register schema empty";
    return false;
  }

  assign_reg_ids(out);
  return true;
}

} // namespace w1rewind
