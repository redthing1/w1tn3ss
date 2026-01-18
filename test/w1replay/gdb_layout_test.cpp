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
  auto target = w1::rewind::test_helpers::make_target_info(w1::rewind::trace_arch::aarch64, 8);
  auto specs = w1::rewind::test_helpers::make_register_specs(trace_regs, w1::rewind::trace_arch::aarch64, 8);
  auto layout = w1replay::gdb::build_register_layout(target, specs);

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
  auto target = w1::rewind::test_helpers::make_target_info(w1::rewind::trace_arch::x86_64, 8);
  auto specs = w1::rewind::test_helpers::make_register_specs(trace_regs, w1::rewind::trace_arch::x86_64, 8);
  auto layout = w1replay::gdb::build_register_layout(target, specs);

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
