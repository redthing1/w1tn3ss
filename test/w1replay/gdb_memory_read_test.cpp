#include <array>
#include <cstddef>
#include <filesystem>
#include <vector>

#include "doctest/doctest.hpp"

#include <redlog.hpp>

#include "w1replay/gdb/adapter.hpp"
#include "w1tn3ss/runtime/rewind/trace_writer.hpp"
#include "w1tn3ss/rewind_test_helpers.hpp"

TEST_CASE("gdb adapter reads recorded memory bytes") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1replay_gdb_mem_read.trace");

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
  header.flags = w1::rewind::trace_flag_instructions | w1::rewind::trace_flag_memory_access |
                 w1::rewind::trace_flag_memory_values;
  REQUIRE(writer->write_header(header));

  write_module_table(*writer, 1, 0x1000);
  write_register_table(*writer, {"pc", "sp"});
  write_thread_start(*writer, 1, "thread1");
  write_instruction(*writer, 1, 0, 1, 0x10);

  w1::rewind::memory_access_record access{};
  access.sequence = 0;
  access.thread_id = 1;
  access.kind = w1::rewind::memory_access_kind::write;
  access.address = 0x3000;
  access.size = 4;
  access.value_known = true;
  access.value_truncated = false;
  access.data = {0xDE, 0xAD, 0xBE, 0xEF};
  REQUIRE(writer->write_memory_access(access));

  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1replay::gdb::adapter::config config;
  config.trace_path = trace_path.string();

  w1replay::gdb::adapter adapter(std::move(config));
  REQUIRE(adapter.open());

  auto target = adapter.make_target();
  std::array<std::byte, 4> buffer{};
  auto status = target.view().mem.read_mem(0x3000, buffer);
  CHECK(status == gdbstub::target_status::ok);
  CHECK(buffer[0] == std::byte{0xDE});
  CHECK(buffer[1] == std::byte{0xAD});
  CHECK(buffer[2] == std::byte{0xBE});
  CHECK(buffer[3] == std::byte{0xEF});
}
