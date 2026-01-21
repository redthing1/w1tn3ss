#include <filesystem>
#include <string>

#include "doctest/doctest.hpp"

#include <redlog.hpp>

#include "w1replay/gdb/adapter.hpp"
#include "w1rewind/rewind_test_helpers.hpp"
#include "w1rewind/trace/trace_file_writer.hpp"

TEST_CASE("gdb host/process info returns best-effort data without target metadata") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1replay_gdb_missing_meta.trace");

  w1::rewind::trace_file_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1replay.gdb");
  writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_file_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  auto arch = parse_arch_or_fail("arm64");
  w1::rewind::trace_header header{};
  header.arch = arch;
  header.flags = w1::rewind::trace_flag_instructions;
  REQUIRE(writer->write_header(header));

  write_thread_start(*writer, 1, "thread1");
  write_instruction(*writer, 1, 0, 0x1000);
  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1replay::gdb::adapter::config config;
  config.trace_path = trace_path.string();

  w1replay::gdb::adapter adapter(std::move(config));
  REQUIRE(adapter.open());

  auto target = adapter.make_target();

  const auto& view = target.view();
  REQUIRE(view.host.has_value());
  auto host_info = view.host->get_host_info();
  REQUIRE(host_info.has_value());
  CHECK(host_info->ptr_size == 8);
  CHECK(host_info->hostname == "w1replay");
  CHECK(host_info->triple.find("aarch64") != std::string::npos);

  REQUIRE(view.process.has_value());
  auto process_info = view.process->get_process_info();
  REQUIRE(process_info.has_value());
  CHECK(process_info->ptr_size == 8);
  CHECK(process_info->pid == 1);
  CHECK(process_info->triple.find("aarch64") != std::string::npos);
}
