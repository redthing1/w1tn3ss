#include <optional>
#include <string>
#include <vector>

#include "doctest/doctest.hpp"

#include "w1replay/gdb/layout.hpp"

namespace {

std::optional<size_t> find_reg_index(const w1replay::gdb::register_layout& layout, const std::string& name) {
  for (size_t i = 0; i < layout.registers.size(); ++i) {
    if (layout.registers[i].name == name) {
      return i;
    }
  }
  return std::nullopt;
}

} // namespace

TEST_CASE("gdb register layout for arm64 is canonical and mapped") {
  std::vector<std::string> trace_regs = {"x0", "x1", "lr", "sp", "pc", "nzcv"};
  auto layout = w1replay::gdb::build_register_layout(w1::rewind::trace_arch::aarch64, 8, trace_regs);

  CHECK(layout.architecture == "aarch64");
  CHECK(layout.feature_name == "org.gnu.gdb.aarch64.core");
  REQUIRE(layout.registers.size() == 34);
  CHECK(layout.pc_reg_num == 32);
  CHECK(layout.sp_reg_num == 31);

  auto x30_idx = find_reg_index(layout, "x30");
  REQUIRE(x30_idx.has_value());
  REQUIRE(layout.registers[*x30_idx].trace_index.has_value());
  CHECK(trace_regs[*layout.registers[*x30_idx].trace_index] == "lr");

  auto cpsr_idx = find_reg_index(layout, "cpsr");
  REQUIRE(cpsr_idx.has_value());
  REQUIRE(layout.registers[*cpsr_idx].trace_index.has_value());
  CHECK(trace_regs[*layout.registers[*cpsr_idx].trace_index] == "nzcv");
}

TEST_CASE("gdb register layout for x86_64 uses eflags and segments") {
  std::vector<std::string> trace_regs = {"rax", "rflags", "fs", "gs", "rip", "rsp"};
  auto layout = w1replay::gdb::build_register_layout(w1::rewind::trace_arch::x86_64, 8, trace_regs);

  CHECK(layout.architecture == "i386:x86-64");
  CHECK(layout.feature_name == "org.gnu.gdb.i386.core");
  REQUIRE(layout.registers.size() >= 24);
  CHECK(layout.pc_reg_num == 16);
  CHECK(layout.sp_reg_num == 7);

  auto eflags_idx = find_reg_index(layout, "eflags");
  REQUIRE(eflags_idx.has_value());
  REQUIRE(layout.registers[*eflags_idx].trace_index.has_value());
  CHECK(trace_regs[*layout.registers[*eflags_idx].trace_index] == "rflags");
}
