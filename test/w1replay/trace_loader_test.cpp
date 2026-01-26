#include <filesystem>

#include "doctest/doctest.hpp"

#include <redlog.hpp>

#include "w1replay/trace_loader/trace_loader.hpp"
#include "w1rewind/rewind_test_helpers.hpp"
#include "w1rewind/trace/trace_index.hpp"

namespace {

void write_simple_trace(const std::filesystem::path& trace_path) {
  using namespace w1::rewind::test_helpers;
  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header(0, 64);
  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1replay.trace_loader"));

  write_basic_metadata(handle.builder, "x86_64", arch, minimal_registers(arch));
  write_thread_start(handle.builder, 1, "thread1");
  write_instruction(handle.builder, 1, 0, 0x1000);
  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->close();
}

} // namespace

TEST_CASE("trace_loader auto-builds index when missing") {
  namespace fs = std::filesystem;

  fs::path trace_path = fs::temp_directory_path() / "w1replay_trace_loader_auto.trace";
  fs::path index_path = fs::temp_directory_path() / "w1replay_trace_loader_auto.trace.w1ridx";

  write_simple_trace(trace_path);
  std::error_code ec;
  fs::remove(index_path, ec);

  w1replay::trace_loader::trace_load_options options;
  options.trace_path = trace_path.string();
  options.index_path = index_path.string();
  options.auto_build_index = true;

  w1replay::trace_loader::trace_load_result result;
  REQUIRE(w1replay::trace_loader::load_trace(options, result));
  REQUIRE(result.index);
  CHECK(result.index->header.anchor_stride != 0);
  CHECK(!result.index->anchors.empty());
  CHECK(fs::exists(index_path));

  fs::remove(index_path, ec);
  fs::remove(trace_path, ec);
}

TEST_CASE("trace_loader fails when index missing and auto-build disabled") {
  namespace fs = std::filesystem;

  fs::path trace_path = fs::temp_directory_path() / "w1replay_trace_loader_missing.trace";
  fs::path index_path = fs::temp_directory_path() / "w1replay_trace_loader_missing.trace.w1ridx";

  write_simple_trace(trace_path);
  std::error_code ec;
  fs::remove(index_path, ec);

  w1replay::trace_loader::trace_load_options options;
  options.trace_path = trace_path.string();
  options.index_path = index_path.string();
  options.auto_build_index = false;

  w1replay::trace_loader::trace_load_result result;
  CHECK_FALSE(w1replay::trace_loader::load_trace(options, result));
  CHECK(result.error == "trace index missing");

  fs::remove(trace_path, ec);
}

TEST_CASE("trace_loader rebuilds index when stride mismatches") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = fs::temp_directory_path() / "w1replay_trace_loader_stride.trace";
  fs::path index_path = fs::temp_directory_path() / "w1replay_trace_loader_stride.trace.w1ridx";

  write_simple_trace(trace_path);

  w1::rewind::trace_index_options build_options;
  build_options.anchor_stride = 1;
  w1::rewind::trace_index initial;
  REQUIRE(w1::rewind::build_trace_index(
      trace_path.string(), index_path.string(), build_options, &initial,
      redlog::get_logger("test.w1replay.trace_loader")
  ));
  REQUIRE(initial.header.anchor_stride == 1);

  w1replay::trace_loader::trace_load_options options;
  options.trace_path = trace_path.string();
  options.index_path = index_path.string();
  options.index_stride = 2;
  options.auto_build_index = true;

  w1replay::trace_loader::trace_load_result result;
  REQUIRE(w1replay::trace_loader::load_trace(options, result));
  REQUIRE(result.index);
  CHECK(result.index->header.anchor_stride == 2);

  std::error_code ec;
  fs::remove(index_path, ec);
  fs::remove(trace_path, ec);
}
