#include <filesystem>

#include "doctest/doctest.hpp"

#include "w1rewind/trace/trace_file_writer.hpp"
#include "w1rewind/trace/trace_reader.hpp"
#include "w1rewind/rewind_test_helpers.hpp"

TEST_CASE("trace reader applies module load and unload records") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_module_events.trace");

  w1::rewind::trace_file_writer_config config;
  config.path = trace_path.string();
  config.log = redlog::get_logger("test.w1rewind.module_events");
  config.chunk_size = 128;

  auto writer = w1::rewind::make_trace_file_writer(config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  auto arch = parse_arch_or_fail("arm64");
  w1::rewind::trace_header header{};
  header.arch = arch;
  header.flags = w1::rewind::trace_flag_instructions;
  REQUIRE(writer->write_header(header));

  write_basic_metadata(*writer, arch, minimal_registers(arch));

  write_module_table(*writer, 1, 0x1000, "module_a");

  w1::rewind::module_record module_b{};
  module_b.id = 2;
  module_b.base = 0x2000;
  module_b.size = 0x1000;
  module_b.permissions = w1::rewind::module_perm::read | w1::rewind::module_perm::exec;
  module_b.path = "module_b";

  w1::rewind::module_load_record load{};
  load.module = module_b;
  REQUIRE(writer->write_module_load(load));

  w1::rewind::module_unload_record unload{};
  unload.module_id = 1;
  unload.base = 0x1000;
  unload.size = 0x1000;
  unload.path = "module_a";
  REQUIRE(writer->write_module_unload(unload));

  writer->flush();
  writer->close();

  w1::rewind::trace_reader reader(trace_path.string());
  REQUIRE(reader.open());

  w1::rewind::trace_record record;
  while (reader.read_next(record)) {
  }

  CHECK(reader.error().empty());
  REQUIRE(reader.module_table().size() == 1);
  CHECK(reader.module_table().front().id == 2);
  CHECK(reader.module_table().front().path == "module_b");

  reader.close();
  fs::remove(trace_path);
}
