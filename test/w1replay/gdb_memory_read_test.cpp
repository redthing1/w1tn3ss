#include <algorithm>
#include <array>
#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

#include "doctest/doctest.hpp"

#include <redlog.hpp>

#include "w1replay/gdb/adapter.hpp"
#include "w1replay/modules/image_bytes.hpp"
#include "w1rewind/trace/trace_file_writer.hpp"
#include "w1rewind/rewind_test_helpers.hpp"

TEST_CASE("gdb adapter reads recorded memory bytes") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1replay_gdb_mem_read.trace");

  auto arch = parse_arch_or_fail("arm64");
  auto header = make_header(0, 64);
  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1replay.gdb"));

  std::vector<std::string> registers = {"pc", "sp"};
  write_basic_metadata(handle.builder, "arm64", arch, registers);
  write_image_mapping(handle.builder, 1, 0x1000, 0x1000);
  write_thread_start(handle.builder, 1, "thread1");
  write_instruction(handle.builder, 1, 0, 0x1000 + 0x10);
  write_memory_access(handle.builder, 1, 0, w1::rewind::mem_access_op::write, 0x3000, {0xDE, 0xAD, 0xBE, 0xEF});
  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->close();

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

TEST_CASE("gdb adapter reads memory access read values") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1replay_gdb_mem_read_access.trace");

  auto arch = parse_arch_or_fail("arm64");
  auto header = make_header(0, 64);
  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1replay.gdb"));

  std::vector<std::string> registers = {"pc"};
  write_basic_metadata(handle.builder, "arm64", arch, registers);
  write_image_mapping(handle.builder, 1, 0x1000, 0x1000);
  write_thread_start(handle.builder, 1, "thread1");
  write_instruction(handle.builder, 1, 0, 0x1000 + 0x10);
  write_memory_access(handle.builder, 1, 0, w1::rewind::mem_access_op::read, 0x4000, {0xFE, 0xED});
  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->close();

  w1replay::gdb::adapter::config config;
  config.trace_path = trace_path.string();

  w1replay::gdb::adapter adapter(std::move(config));
  REQUIRE(adapter.open());

  auto target = adapter.make_target();
  std::array<std::byte, 2> buffer{};
  auto status = target.view().mem.read_mem(0x4000, buffer);
  CHECK(status == gdbstub::target_status::ok);
  CHECK(buffer[0] == std::byte{0xFE});
  CHECK(buffer[1] == std::byte{0xED});
}

TEST_CASE("gdb adapter reads image bytes when memory missing") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1replay_gdb_image_mem.trace");

  auto arch = parse_arch_or_fail("arm64");
  auto header = make_header(0, 64);
  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1replay.gdb"));

  std::vector<std::string> registers = {"pc"};
  write_basic_metadata(handle.builder, "arm64", arch, registers);
  write_image_mapping(handle.builder, 1, 0x1000, 0x1000);
  write_thread_start(handle.builder, 1, "thread1");
  write_instruction(handle.builder, 1, 0, 0x1000 + 0x10);
  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->close();

  w1replay::gdb::adapter::config config;
  config.trace_path = trace_path.string();
  config.image_reader = [](uint32_t, uint64_t addr, size_t size) {
    auto result = w1replay::make_empty_image_read(size);
    for (size_t i = 0; i < size; ++i) {
      result.bytes[i] = static_cast<std::byte>(0xA0 + (addr + i) % 16);
      result.known[i] = 1;
    }
    result.complete = true;
    return result;
  };

  w1replay::gdb::adapter adapter(std::move(config));
  REQUIRE(adapter.open());

  auto target = adapter.make_target();
  std::array<std::byte, 4> buffer{};
  auto status = target.view().mem.read_mem(0x1010, buffer);
  CHECK(status == gdbstub::target_status::ok);
  CHECK(buffer[0] == std::byte{0xA0});
}

TEST_CASE("gdb adapter prefers recorded memory over image bytes") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1replay_gdb_recorded_overrides.trace");

  auto arch = parse_arch_or_fail("arm64");
  auto header = make_header(0, 64);
  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1replay.gdb"));

  std::vector<std::string> registers = {"pc", "sp"};
  write_basic_metadata(handle.builder, "arm64", arch, registers);
  write_image_mapping(handle.builder, 1, 0x1000, 0x1000);
  write_thread_start(handle.builder, 1, "thread1");
  write_instruction(handle.builder, 1, 0, 0x1000 + 0x10);

  write_memory_access(handle.builder, 1, 0, w1::rewind::mem_access_op::write, 0x1010, {0x11, 0x22, 0x33, 0x44});

  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->close();

  w1replay::gdb::adapter::config config;
  config.trace_path = trace_path.string();
  config.image_reader = [](uint32_t, uint64_t, size_t size) {
    auto result = w1replay::make_empty_image_read(size);
    for (auto& byte : result.bytes) {
      byte = std::byte{0xFF};
    }
    std::fill(result.known.begin(), result.known.end(), 1);
    result.complete = true;
    return result;
  };

  w1replay::gdb::adapter adapter(std::move(config));
  REQUIRE(adapter.open());

  auto target = adapter.make_target();
  std::array<std::byte, 4> buffer{};
  auto status = target.view().mem.read_mem(0x1010, buffer);
  CHECK(status == gdbstub::target_status::ok);
  CHECK(buffer[0] == std::byte{0x11});
  CHECK(buffer[1] == std::byte{0x22});
  CHECK(buffer[2] == std::byte{0x33});
  CHECK(buffer[3] == std::byte{0x44});
}
