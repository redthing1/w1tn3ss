#include <filesystem>
#include <vector>

#include "doctest/doctest.hpp"

#include <redlog.hpp>

#include "w1replay/gdb/adapter.hpp"
#include "w1rewind/rewind_test_helpers.hpp"

namespace {

std::filesystem::path write_trace_with_images(const char* name) {
  using namespace w1::rewind::test_helpers;

  std::filesystem::path trace_path = temp_path(name);

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header(0, 64);
  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1replay.gdb"));

  write_basic_metadata(handle.builder, "x86_64", arch, minimal_registers(arch));

  w1::rewind::image_record main{};
  main.image_id = 1;
  main.name = "main";
  main.identity = "/tmp/main.exe";
  main.path = "/tmp/main.exe";
  main.flags = w1::rewind::image_flag_main | w1::rewind::image_flag_file_backed;
  REQUIRE(handle.builder.emit_image(main));

  w1::rewind::image_record shared{};
  shared.image_id = 2;
  shared.name = "libfoo";
  shared.identity = "/lib/libfoo.so";
  shared.path = "/lib/libfoo.so";
  shared.flags = w1::rewind::image_flag_file_backed;
  REQUIRE(handle.builder.emit_image(shared));

  w1::rewind::image_record heap{};
  heap.image_id = 3;
  heap.name = "[heap]";
  REQUIRE(handle.builder.emit_image(heap));

  w1::rewind::image_record stack{};
  stack.image_id = 4;
  stack.name = "[stack]";
  REQUIRE(handle.builder.emit_image(stack));

  w1::rewind::mapping_record main_map{};
  main_map.space_id = 0;
  main_map.base = 0x400000;
  main_map.size = 0x1000;
  main_map.perms = w1::rewind::mapping_perm::read | w1::rewind::mapping_perm::exec;
  main_map.image_id = 1;
  main_map.name = main.identity;
  REQUIRE(handle.builder.emit_mapping(main_map));

  w1::rewind::mapping_record shared_map{};
  shared_map.space_id = 0;
  shared_map.base = 0x500000;
  shared_map.size = 0x1000;
  shared_map.perms = w1::rewind::mapping_perm::read | w1::rewind::mapping_perm::exec;
  shared_map.image_id = 2;
  shared_map.name = shared.identity;
  REQUIRE(handle.builder.emit_mapping(shared_map));

  w1::rewind::mapping_record heap_map{};
  heap_map.space_id = 0;
  heap_map.base = 0x600000;
  heap_map.size = 0x1000;
  heap_map.perms = w1::rewind::mapping_perm::read | w1::rewind::mapping_perm::write;
  heap_map.image_id = 3;
  heap_map.name = heap.name;
  REQUIRE(handle.builder.emit_mapping(heap_map));

  w1::rewind::mapping_record stack_map{};
  stack_map.space_id = 0;
  stack_map.base = 0x700000;
  stack_map.size = 0x1000;
  stack_map.perms = w1::rewind::mapping_perm::read | w1::rewind::mapping_perm::write;
  stack_map.image_id = 4;
  stack_map.name = stack.name;
  REQUIRE(handle.builder.emit_mapping(stack_map));

  write_thread_start(handle.builder, 1, "thread1");
  write_instruction(handle.builder, 1, 0, 0x400100);
  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->flush();
  handle.writer->close();
  return trace_path;
}

} // namespace

TEST_CASE("gdb libraries list omits main image and pseudo entries") {
  auto trace_path = write_trace_with_images("w1replay_gdb_libraries.trace");

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
