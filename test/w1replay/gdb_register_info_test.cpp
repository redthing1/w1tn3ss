#include <filesystem>
#include <string>
#include <vector>

#include "doctest/doctest.hpp"

#include <redlog.hpp>

#include "w1replay/gdb/adapter.hpp"
#include "w1replay/gdb/layout.hpp"
#include "w1rewind/record/trace_writer.hpp"
#include "w1rewind/rewind_test_helpers.hpp"

TEST_CASE("gdb adapter exposes register info with pc/sp generics") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1replay_gdb_reginfo.trace");

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

  std::vector<std::string> registers = {"x0", "sp", "pc", "nzcv"};

  write_target_info(*writer, w1::rewind::trace_arch::aarch64, 8);
  write_register_specs(*writer, registers, w1::rewind::trace_arch::aarch64, 8);
  write_module_table(*writer, 1, 0x1000);
  write_thread_start(*writer, 1, "thread1");
  write_instruction(*writer, 1, 0, 1, 0x10);
  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1replay::gdb::adapter::config config;
  config.trace_path = trace_path.string();

  w1replay::gdb::adapter adapter(std::move(config));
  REQUIRE(adapter.open());

  auto gdb_target = adapter.make_target();
  REQUIRE(gdb_target.view().reg_info.has_value());

  auto target_info = w1::rewind::test_helpers::make_target_info(w1::rewind::trace_arch::aarch64, 8);
  auto specs = w1::rewind::test_helpers::make_register_specs(registers, w1::rewind::trace_arch::aarch64, 8);
  auto layout = w1replay::gdb::build_register_layout(target_info, specs);
  REQUIRE(layout.pc_reg_num >= 0);
  REQUIRE(layout.sp_reg_num >= 0);

  auto pc_info = gdb_target.view().reg_info->get_register_info(layout.pc_reg_num);
  REQUIRE(pc_info.has_value());
  CHECK(pc_info->generic.has_value());
  CHECK(*pc_info->generic == "pc");

  auto sp_info = gdb_target.view().reg_info->get_register_info(layout.sp_reg_num);
  REQUIRE(sp_info.has_value());
  CHECK(sp_info->generic.has_value());
  CHECK(*sp_info->generic == "sp");
}
