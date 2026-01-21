#include <optional>
#include <string>
#include <vector>

#include "doctest/doctest.hpp"

#include "w1replay/gdb/layout.hpp"
#include "w1rewind/rewind_test_helpers.hpp"

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
  auto arch = w1::rewind::test_helpers::parse_arch_or_fail("arm64");
  auto specs = w1::rewind::test_helpers::make_register_specs(trace_regs, arch);
  auto layout = w1replay::gdb::build_register_layout(arch, specs);

  CHECK(layout.architecture == "aarch64");
  CHECK(layout.feature_name == "org.gnu.gdb.aarch64.core");
  REQUIRE(layout.registers.size() == 6);
  CHECK(layout.pc_reg_num == 4);
  CHECK(layout.sp_reg_num == 3);

  auto cpsr_idx = find_reg_index(layout, "cpsr");
  REQUIRE(cpsr_idx.has_value());
  REQUIRE(layout.registers[*cpsr_idx].trace_index.has_value());
  CHECK(trace_regs[*layout.registers[*cpsr_idx].trace_index] == "nzcv");
}

TEST_CASE("gdb register layout for x86_64 uses eflags and segments") {
  std::vector<std::string> trace_regs = {"rax", "rflags", "fs", "gs", "rip", "rsp"};
  auto arch = w1::rewind::test_helpers::parse_arch_or_fail("x86_64");
  auto specs = w1::rewind::test_helpers::make_register_specs(trace_regs, arch);
  auto layout = w1replay::gdb::build_register_layout(arch, specs);

  CHECK(layout.architecture == "i386:x86-64");
  CHECK(layout.feature_name == "org.gnu.gdb.i386.core");
  REQUIRE(layout.registers.size() == 6);
  CHECK(layout.pc_reg_num == 4);
  CHECK(layout.sp_reg_num == 5);

  auto eflags_idx = find_reg_index(layout, "eflags");
  REQUIRE(eflags_idx.has_value());
  REQUIRE(layout.registers[*eflags_idx].trace_index.has_value());
  CHECK(trace_regs[*layout.registers[*eflags_idx].trace_index] == "rflags");
}

TEST_CASE("gdb register layout falls back to minimal registers when specs are missing") {
  auto arch = w1::rewind::test_helpers::parse_arch_or_fail("arm64");
  std::vector<w1::rewind::register_spec> specs;
  auto layout = w1replay::gdb::build_register_layout(arch, specs);

  REQUIRE(layout.registers.size() == 3);
  auto pc_idx = find_reg_index(layout, "pc");
  auto sp_idx = find_reg_index(layout, "sp");
  auto cpsr_idx = find_reg_index(layout, "cpsr");
  REQUIRE(pc_idx.has_value());
  REQUIRE(sp_idx.has_value());
  REQUIRE(cpsr_idx.has_value());
  CHECK(layout.registers[*pc_idx].is_pc);
  CHECK(layout.registers[*sp_idx].is_sp);
  CHECK(layout.registers[*cpsr_idx].is_flags);
}
