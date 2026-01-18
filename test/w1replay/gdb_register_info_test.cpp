#include <filesystem>
#include <string>
#include <vector>

#include "doctest/doctest.hpp"

#include <redlog.hpp>

#include "w1replay/gdb/adapter.hpp"
#include "w1replay/gdb/layout.hpp"
#include "w1tn3ss/runtime/rewind/trace_writer.hpp"
#include "w1tn3ss/rewind_test_helpers.hpp"

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

  write_module_table(*writer, 1, 0x1000);
  write_register_table(*writer, registers);
  write_thread_start(*writer, 1, "thread1");
  write_instruction(*writer, 1, 0, 1, 0x10);
  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1replay::gdb::adapter::config config;
  config.trace_path = trace_path.string();

  w1replay::gdb::adapter adapter(std::move(config));
  REQUIRE(adapter.open());

  auto target = adapter.make_target();
  REQUIRE(target.view().reg_info.has_value());

  auto layout = w1replay::gdb::build_register_layout(
      w1::rewind::trace_arch::aarch64,
      8,
      registers
  );
  REQUIRE(layout.pc_reg_num >= 0);
  REQUIRE(layout.sp_reg_num >= 0);

  auto pc_info = target.view().reg_info->get_register_info(layout.pc_reg_num);
  REQUIRE(pc_info.has_value());
  CHECK(pc_info->generic.has_value());
  CHECK(*pc_info->generic == "pc");

  auto sp_info = target.view().reg_info->get_register_info(layout.sp_reg_num);
  REQUIRE(sp_info.has_value());
  CHECK(sp_info->generic.has_value());
  CHECK(*sp_info->generic == "sp");
}
