#include "w1rewind/format/register_numbering.hpp"

#include <array>
#include <charconv>
#include <string_view>
#include <system_error>

namespace w1::rewind {
namespace {

// DWARF/EHFrame numbering derived from lldb register tables
std::optional<uint32_t> parse_prefixed_number(
    std::string_view name, char prefix, uint32_t min_value, uint32_t max_value
) {
  if (name.size() < 2 || name.front() != prefix) {
    return std::nullopt;
  }
  uint32_t value = 0;
  const char* start = name.data() + 1;
  const char* end = name.data() + name.size();
  auto [ptr, ec] = std::from_chars(start, end, value);
  if (ec != std::errc() || ptr != end) {
    return std::nullopt;
  }
  if (value < min_value || value > max_value) {
    return std::nullopt;
  }
  return value;
}

register_numbering make_numbering(uint32_t regnum) {
  register_numbering numbering{};
  numbering.dwarf_regnum = regnum;
  numbering.ehframe_regnum = regnum;
  return numbering;
}

std::optional<register_numbering> lookup_aarch64(std::string_view name) {
  if (name == "sp") {
    return make_numbering(31);
  }
  if (name == "pc") {
    return make_numbering(32);
  }
  if (name == "cpsr" || name == "nzcv") {
    return make_numbering(33);
  }
  if (name == "fp") {
    return make_numbering(29);
  }
  if (name == "lr") {
    return make_numbering(30);
  }
  if (auto value = parse_prefixed_number(name, 'x', 0, 31)) {
    return make_numbering(*value);
  }
  return std::nullopt;
}

std::optional<register_numbering> lookup_arm32(std::string_view name) {
  if (name == "sp") {
    return make_numbering(13);
  }
  if (name == "lr") {
    return make_numbering(14);
  }
  if (name == "pc") {
    return make_numbering(15);
  }
  if (name == "cpsr") {
    return make_numbering(16);
  }
  if (auto value = parse_prefixed_number(name, 'r', 0, 15)) {
    return make_numbering(*value);
  }
  return std::nullopt;
}

std::optional<register_numbering> lookup_x86_32(std::string_view name) {
  static constexpr std::array<std::pair<std::string_view, uint32_t>, 10> kMap = {{
      {"eax", 0},
      {"ecx", 1},
      {"edx", 2},
      {"ebx", 3},
      {"esp", 4},
      {"ebp", 5},
      {"esi", 6},
      {"edi", 7},
      {"eip", 8},
      {"eflags", 9},
  }};
  for (const auto& [reg_name, regnum] : kMap) {
    if (name == reg_name) {
      return make_numbering(regnum);
    }
  }
  return std::nullopt;
}

std::optional<register_numbering> lookup_x86_64(std::string_view name) {
  static constexpr std::array<std::pair<std::string_view, uint32_t>, 25> kMap = {{
      {"rax", 0},  {"rdx", 1},  {"rcx", 2},  {"rbx", 3},     {"rsi", 4},     {"rdi", 5},  {"rbp", 6},
      {"rsp", 7},  {"r8", 8},   {"r9", 9},   {"r10", 10},    {"r11", 11},    {"r12", 12}, {"r13", 13},
      {"r14", 14}, {"r15", 15}, {"rip", 16}, {"rflags", 49}, {"eflags", 49}, {"es", 50},  {"cs", 51},
      {"ss", 52},  {"ds", 53},  {"fs", 54},  {"gs", 55},
  }};
  for (const auto& [reg_name, regnum] : kMap) {
    if (name == reg_name) {
      return make_numbering(regnum);
    }
  }
  return std::nullopt;
}

} // namespace

std::optional<register_numbering> lookup_register_numbering(const w1::arch::arch_spec& arch, std::string_view name) {
  switch (arch.arch_mode) {
  case w1::arch::mode::aarch64:
    return lookup_aarch64(name);
  case w1::arch::mode::arm:
  case w1::arch::mode::thumb:
    return lookup_arm32(name);
  case w1::arch::mode::x86_64:
    return lookup_x86_64(name);
  case w1::arch::mode::x86_32:
    return lookup_x86_32(name);
  default:
    break;
  }
  return std::nullopt;
}

} // namespace w1::rewind
