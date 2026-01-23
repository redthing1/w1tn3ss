#include <filesystem>
#include <vector>

#include "doctest/doctest.hpp"

#include <redlog.hpp>

#include "w1replay/gdb/adapter.hpp"
#include "w1rewind/trace/trace_file_writer.hpp"
#include "w1rewind/rewind_test_helpers.hpp"

namespace {

std::filesystem::path write_trace_with_modules(const char* name) {
  using namespace w1::rewind::test_helpers;

  std::filesystem::path trace_path = temp_path(name);

  w1::rewind::trace_file_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1replay.gdb");
  writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_file_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  auto arch = parse_arch_or_fail("x86_64");
  w1::rewind::trace_header header{};
  header.arch = arch;
  header.flags = w1::rewind::trace_flag_instructions;
  REQUIRE(writer->write_header(header));

  write_basic_metadata(*writer, arch, minimal_registers(arch));

  w1::rewind::module_table_record table{};
  w1::rewind::module_record main{};
  main.id = 1;
  main.base = 0x400000;
  main.size = 0x1000;
  main.permissions = w1::rewind::module_perm::read | w1::rewind::module_perm::exec;
  main.path = "/tmp/main.exe";
  main.flags = w1::rewind::module_record_flag_main | w1::rewind::module_record_flag_file_backed;
  table.modules.push_back(main);

  w1::rewind::module_record shared{};
  shared.id = 2;
  shared.base = 0x500000;
  shared.size = 0x1000;
  shared.permissions = w1::rewind::module_perm::read | w1::rewind::module_perm::exec;
  shared.path = "/lib/libfoo.so";
  shared.flags = w1::rewind::module_record_flag_file_backed;
  table.modules.push_back(shared);

  w1::rewind::module_record heap{};
  heap.id = 3;
  heap.base = 0x600000;
  heap.size = 0x1000;
  heap.permissions = w1::rewind::module_perm::read | w1::rewind::module_perm::write;
  heap.path = "[heap]";
  table.modules.push_back(heap);

  w1::rewind::module_record stack{};
  stack.id = 4;
  stack.base = 0x700000;
  stack.size = 0x1000;
  stack.permissions = w1::rewind::module_perm::read | w1::rewind::module_perm::write;
  stack.path = "[stack]";
  table.modules.push_back(stack);
  REQUIRE(writer->write_module_table(table));

  write_thread_start(*writer, 1, "thread1");
  write_instruction(*writer, 1, 0, 0x400100);
  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();
  return trace_path;
}

} // namespace

TEST_CASE("gdb libraries list omits main module and pseudo entries") {
  auto trace_path = write_trace_with_modules("w1replay_gdb_libraries.trace");

  w1replay::gdb::adapter::config config;
  config.trace_path = trace_path.string();

  w1replay::gdb::adapter adapter(std::move(config));
  REQUIRE(adapter.open());

  auto target = adapter.make_target();
  REQUIRE(target.view().libraries.has_value());

  auto entries = target.view().libraries->libraries();
  REQUIRE(entries.size() == 1);
  CHECK(entries[0].name == "/lib/libfoo.so");

  auto generation = target.view().libraries->generation();
  REQUIRE(generation.has_value());
  CHECK(*generation == 1);
}
