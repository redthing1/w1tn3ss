#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "doctest/doctest.hpp"

#include <redlog.hpp>

#include "w1replay/gdb/adapter.hpp"
#include "w1replay/gdb/layout.hpp"
#include "w1rewind/rewind_test_helpers.hpp"

namespace {
std::unique_ptr<w1replay::gdb::adapter> open_adapter_with_registers(
    const char* trace_name, std::string_view arch_id, const w1::arch::arch_spec& arch,
    const std::vector<std::string>& registers
) {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path(trace_name);

  auto header = make_header(0, 64);
  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1replay.gdb"));

  write_basic_metadata(handle.builder, arch_id, arch, registers);
  write_image_mapping(handle.builder, 1, 0x1000, 0x1000);
  write_thread_start(handle.builder, 1, "thread1");
  write_instruction(handle.builder, 1, 0, 0x1000 + 0x10);
  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->flush();
  handle.writer->close();

  w1replay::gdb::adapter::config config;
  config.trace_path = trace_path.string();

  auto adapter = std::make_unique<w1replay::gdb::adapter>(std::move(config));
  REQUIRE(adapter->open());
  return adapter;
}

int find_reg_num(const w1replay::gdb::register_layout& layout, std::string_view name) {
  for (size_t i = 0; i < layout.registers.size(); ++i) {
    if (layout.registers[i].name == name) {
      return static_cast<int>(i);
    }
  }
  return -1;
}
} // namespace

TEST_CASE("gdb adapter exposes register info with pc/sp generics") {
  using namespace w1::rewind::test_helpers;

  auto arch = parse_arch_or_fail("arm64");

  std::vector<std::string> registers = {"x0", "sp", "pc", "nzcv"};
  auto adapter = open_adapter_with_registers("w1replay_gdb_reginfo.trace", "arm64", arch, registers);

  auto gdb_target = adapter->make_target();
  REQUIRE(gdb_target.view().reg_info.has_value());

  auto specs = w1::rewind::test_helpers::make_register_specs(registers, arch);
  w1::rewind::replay_context context{};
  context.arch = w1::rewind::test_helpers::make_arch_descriptor("arm64", arch);
  auto layout = w1replay::gdb::build_register_layout(context, specs);
  REQUIRE(layout.pc_reg_num >= 0);
  REQUIRE(layout.sp_reg_num >= 0);

  auto pc_info = gdb_target.view().reg_info->get_register_info(layout.pc_reg_num);
  REQUIRE(pc_info.has_value());
  CHECK(pc_info->generic.has_value());
  CHECK(*pc_info->generic == "pc");
  CHECK(pc_info->dwarf_regnum.has_value());
  CHECK(*pc_info->dwarf_regnum == 32);
  CHECK(pc_info->gcc_regnum.has_value());
  CHECK(*pc_info->gcc_regnum == 32);

  auto sp_info = gdb_target.view().reg_info->get_register_info(layout.sp_reg_num);
  REQUIRE(sp_info.has_value());
  CHECK(sp_info->generic.has_value());
  CHECK(*sp_info->generic == "sp");
  CHECK(sp_info->dwarf_regnum.has_value());
  CHECK(*sp_info->dwarf_regnum == 31);
  CHECK(sp_info->gcc_regnum.has_value());
  CHECK(*sp_info->gcc_regnum == 31);

  int x0_reg_num = find_reg_num(layout, "x0");
  REQUIRE(x0_reg_num >= 0);
  auto x0_info = gdb_target.view().reg_info->get_register_info(x0_reg_num);
  REQUIRE(x0_info.has_value());
  CHECK(x0_info->dwarf_regnum.has_value());
  CHECK(*x0_info->dwarf_regnum == 0);
  CHECK(x0_info->gcc_regnum.has_value());
  CHECK(*x0_info->gcc_regnum == 0);

  int cpsr_reg_num = find_reg_num(layout, "cpsr");
  REQUIRE(cpsr_reg_num >= 0);
  auto cpsr_info = gdb_target.view().reg_info->get_register_info(cpsr_reg_num);
  REQUIRE(cpsr_info.has_value());
  CHECK(cpsr_info->dwarf_regnum.has_value());
  CHECK(*cpsr_info->dwarf_regnum == 33);
  CHECK(cpsr_info->gcc_regnum.has_value());
  CHECK(*cpsr_info->gcc_regnum == 33);
}

TEST_CASE("gdb adapter exposes dwarf numbers for x86_64 gprs") {
  using namespace w1::rewind::test_helpers;

  auto arch = parse_arch_or_fail("x86_64");
  std::vector<std::string> registers = {"rax", "rbp", "rsp", "rip", "eflags"};

  auto adapter = open_adapter_with_registers("w1replay_gdb_reginfo_x86_64.trace", "x86_64", arch, registers);
  auto gdb_target = adapter->make_target();
  REQUIRE(gdb_target.view().reg_info.has_value());

  auto specs = w1::rewind::test_helpers::make_register_specs(registers, arch);
  w1::rewind::replay_context context{};
  context.arch = w1::rewind::test_helpers::make_arch_descriptor("x86_64", arch);
  auto layout = w1replay::gdb::build_register_layout(context, specs);

  int rip_reg_num = find_reg_num(layout, "rip");
  REQUIRE(rip_reg_num >= 0);
  auto rip_info = gdb_target.view().reg_info->get_register_info(rip_reg_num);
  REQUIRE(rip_info.has_value());
  CHECK(rip_info->dwarf_regnum.has_value());
  CHECK(*rip_info->dwarf_regnum == 16);
  CHECK(rip_info->gcc_regnum.has_value());
  CHECK(*rip_info->gcc_regnum == 16);

  int rsp_reg_num = find_reg_num(layout, "rsp");
  REQUIRE(rsp_reg_num >= 0);
  auto rsp_info = gdb_target.view().reg_info->get_register_info(rsp_reg_num);
  REQUIRE(rsp_info.has_value());
  CHECK(rsp_info->dwarf_regnum.has_value());
  CHECK(*rsp_info->dwarf_regnum == 7);
  CHECK(rsp_info->gcc_regnum.has_value());
  CHECK(*rsp_info->gcc_regnum == 7);

  int rax_reg_num = find_reg_num(layout, "rax");
  REQUIRE(rax_reg_num >= 0);
  auto rax_info = gdb_target.view().reg_info->get_register_info(rax_reg_num);
  REQUIRE(rax_info.has_value());
  CHECK(rax_info->dwarf_regnum.has_value());
  CHECK(*rax_info->dwarf_regnum == 0);
  CHECK(rax_info->gcc_regnum.has_value());
  CHECK(*rax_info->gcc_regnum == 0);

  int rbp_reg_num = find_reg_num(layout, "rbp");
  REQUIRE(rbp_reg_num >= 0);
  auto rbp_info = gdb_target.view().reg_info->get_register_info(rbp_reg_num);
  REQUIRE(rbp_info.has_value());
  CHECK(rbp_info->dwarf_regnum.has_value());
  CHECK(*rbp_info->dwarf_regnum == 6);
  CHECK(rbp_info->gcc_regnum.has_value());
  CHECK(*rbp_info->gcc_regnum == 6);

  int eflags_reg_num = find_reg_num(layout, "eflags");
  REQUIRE(eflags_reg_num >= 0);
  auto eflags_info = gdb_target.view().reg_info->get_register_info(eflags_reg_num);
  REQUIRE(eflags_info.has_value());
  CHECK(eflags_info->dwarf_regnum.has_value());
  CHECK(*eflags_info->dwarf_regnum == 49);
  CHECK(eflags_info->gcc_regnum.has_value());
  CHECK(*eflags_info->gcc_regnum == 49);
}
