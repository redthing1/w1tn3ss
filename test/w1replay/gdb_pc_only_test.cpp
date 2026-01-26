#include <cstddef>
#include <filesystem>
#include <vector>

#include "doctest/doctest.hpp"

#include <redlog.hpp>

#include "w1replay/gdb/adapter.hpp"
#include "w1rewind/rewind_test_helpers.hpp"

TEST_CASE("gdb adapter opens pc-only trace with minimal register specs") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1replay_gdb_pc_only.trace");

  auto arch = parse_arch_or_fail("arm64");
  auto header = make_header(0, 64);
  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1replay.gdb"));

  std::vector<std::string> registers = {"x0", "pc"};
  write_basic_metadata(handle.builder, "arm64", arch, registers);
  write_image_mapping(handle.builder, 1, 0x1000, 0x1000);
  write_thread_start(handle.builder, 1, "thread1");
  write_instruction(handle.builder, 1, 0, 0x1000 + 0x40);
  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->flush();
  handle.writer->close();

  w1replay::gdb::adapter::config config;
  config.trace_path = trace_path.string();

  w1replay::gdb::adapter adapter(std::move(config));
  REQUIRE(adapter.open());
  CHECK(adapter.session().current_step().address == 0x1040);
  CHECK(adapter.arch_spec().pc_reg_num >= 0);
  CHECK(!adapter.arch_spec().target_xml.empty());

  auto target = adapter.make_target();
  int pc_reg = adapter.arch_spec().pc_reg_num;
  REQUIRE(pc_reg >= 0);
  size_t pc_size = target.view().regs.reg_size(pc_reg);
  REQUIRE(pc_size == 8);
  std::vector<std::byte> buffer(pc_size);
  auto status = target.view().regs.read_reg(pc_reg, buffer);
  CHECK(status == gdbstub::target_status::ok);
  uint64_t pc_value = 0;
  for (size_t i = 0; i < buffer.size(); ++i) {
    pc_value |= static_cast<uint64_t>(std::to_integer<uint8_t>(buffer[i])) << (i * 8);
  }
  CHECK(pc_value == adapter.session().current_step().address);

  std::vector<std::byte> reg0(pc_size);
  auto reg0_status = target.view().regs.read_reg(0, reg0);
  CHECK(reg0_status == gdbstub::target_status::ok);
  for (auto byte : reg0) {
    CHECK(std::to_integer<uint8_t>(byte) == 0xcc);
  }
}
