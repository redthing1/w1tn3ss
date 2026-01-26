#include <filesystem>
#include <string>

#include "doctest/doctest.hpp"

#include <redlog.hpp>

#include "w1replay/gdb/adapter.hpp"
#include "w1rewind/rewind_test_helpers.hpp"

TEST_CASE("gdb host/process info reflects environment metadata when provided") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1replay_gdb_missing_meta.trace");

  auto arch = parse_arch_or_fail("arm64");
  auto header = make_header(0, 64);
  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1replay.gdb"));

  REQUIRE(handle.builder.emit_arch_descriptor(make_arch_descriptor("arm64", arch)));
  REQUIRE(handle.builder.emit_environment(make_environment()));
  REQUIRE(handle.builder.emit_address_space(make_address_space(0, arch)));
  REQUIRE(handle.builder.emit_register_file(make_register_file(0, {"pc"}, arch)));

  write_thread_start(handle.builder, 1, "thread1");
  write_instruction(handle.builder, 1, 0, 0x1000);
  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->flush();
  handle.writer->close();

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
  CHECK(host_info->hostname == "test-host");
  CHECK(host_info->triple.find("aarch64") != std::string::npos);

  REQUIRE(view.process.has_value());
  auto process_info = view.process->get_process_info();
  REQUIRE(process_info.has_value());
  CHECK(process_info->ptr_size == 8);
  CHECK(process_info->pid == 42);
  CHECK(process_info->ostype == "test");
  CHECK(process_info->triple.find("aarch64") != std::string::npos);
}

TEST_CASE("gdb host/process info uses unknown values when environment is empty") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1replay_gdb_unknown_env.trace");

  auto arch = parse_arch_or_fail("arm64");
  auto header = make_header(0, 64);
  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1replay.gdb"));

  REQUIRE(handle.builder.emit_arch_descriptor(make_arch_descriptor("arm64", arch)));
  w1::rewind::environment_record env{};
  REQUIRE(handle.builder.emit_environment(env));
  REQUIRE(handle.builder.emit_address_space(make_address_space(0, arch)));
  REQUIRE(handle.builder.emit_register_file(make_register_file(0, {"pc"}, arch)));

  write_thread_start(handle.builder, 1, "thread1");
  write_instruction(handle.builder, 1, 0, 0x1000);
  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->flush();
  handle.writer->close();

  w1replay::gdb::adapter::config config;
  config.trace_path = trace_path.string();

  w1replay::gdb::adapter adapter(std::move(config));
  REQUIRE(adapter.open());

  auto target = adapter.make_target();
  const auto& view = target.view();
  REQUIRE(view.host.has_value());
  auto host_info = view.host->get_host_info();
  REQUIRE(host_info.has_value());
  CHECK(host_info->hostname == "w1replay");
  CHECK(host_info->triple.find("unknown") != std::string::npos);

  REQUIRE(view.process.has_value());
  auto process_info = view.process->get_process_info();
  REQUIRE(process_info.has_value());
  CHECK(process_info->ostype == "unknown");
  CHECK(process_info->triple.find("unknown") != std::string::npos);
}
