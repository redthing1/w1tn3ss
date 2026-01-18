#include <cstddef>
#include <filesystem>
#include <vector>

#include "doctest/doctest.hpp"

#include <redlog.hpp>

#include "w1replay/gdb/adapter.hpp"
#include "w1rewind/record/trace_writer.hpp"
#include "w1rewind/rewind_test_helpers.hpp"

TEST_CASE("gdb adapter opens pc-only trace without register table") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1replay_gdb_pc_only.trace");

  w1::rewind::trace_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1replay.gdb");
  writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1::rewind::trace_header header{};
  header.architecture = w1::rewind::trace_arch::aarch64;
  header.pointer_size = 8;
  header.flags = w1::rewind::trace_flag_instructions;
  REQUIRE(writer->write_header(header));

  write_module_table(*writer, 1, 0x1000);
  write_thread_start(*writer, 1, "thread1");
  write_instruction(*writer, 1, 0, 1, 0x40);
  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

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
