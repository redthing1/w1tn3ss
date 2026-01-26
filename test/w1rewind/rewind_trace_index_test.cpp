#include <filesystem>

#include "doctest/doctest.hpp"

#include "w1rewind/rewind_test_helpers.hpp"
#include "w1rewind/trace/trace_index.hpp"
#include "w1rewind/trace/trace_reader.hpp"

namespace {

void write_instruction_range(
    w1::rewind::trace_builder& builder, uint64_t thread_id, uint64_t start_seq, uint64_t count, uint64_t base_address
) {
  for (uint64_t i = 0; i < count; ++i) {
    w1::rewind::test_helpers::write_instruction(builder, thread_id, start_seq + i, base_address + 0x100 + i * 4, 4);
  }
}

} // namespace

TEST_CASE("w1rewind trace index builds anchors for instruction flow") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = fs::temp_directory_path() / "w1rewind_index.trace";
  fs::path index_path = fs::temp_directory_path() / "w1rewind_index.trace.w1ridx";

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header();
  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1rewind.index"));

  write_basic_metadata(handle.builder, "x86_64", arch, minimal_registers(arch));
  w1::rewind::thread_start_record start1{};
  start1.thread_id = 1;
  start1.name = "thread1";
  REQUIRE(handle.builder.emit_thread_start(start1));

  w1::rewind::thread_start_record start2{};
  start2.thread_id = 2;
  start2.name = "thread2";
  REQUIRE(handle.builder.emit_thread_start(start2));

  write_instruction_range(handle.builder, 1, 0, 10, 0x1000);
  write_instruction_range(handle.builder, 2, 0, 5, 0x2000);

  w1::rewind::thread_end_record end1{};
  end1.thread_id = 1;
  REQUIRE(handle.builder.emit_thread_end(end1));

  w1::rewind::thread_end_record end2{};
  end2.thread_id = 2;
  REQUIRE(handle.builder.emit_thread_end(end2));

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_index_options options;
  options.anchor_stride = 3;

  w1::rewind::trace_index index;
  REQUIRE(
      w1::rewind::build_trace_index(
          trace_path.string(), index_path.string(), options, &index, redlog::get_logger("test.w1rewind.index")
      )
  );

  w1::rewind::trace_index loaded;
  REQUIRE(w1::rewind::load_trace_index(index_path.string(), loaded, redlog::get_logger("test.w1rewind.index")));

  CHECK(loaded.header.anchor_stride == options.anchor_stride);
  CHECK(loaded.threads.size() == 2);

  auto anchor1 = loaded.find_anchor(1, 5);
  REQUIRE(anchor1.has_value());
  CHECK(anchor1->sequence == 3);

  auto anchor2 = loaded.find_anchor(1, 9);
  REQUIRE(anchor2.has_value());
  CHECK(anchor2->sequence == 9);

  auto anchor3 = loaded.find_anchor(2, 2);
  REQUIRE(anchor3.has_value());
  CHECK(anchor3->sequence == 0);
}

TEST_CASE("w1rewind trace index rebuilds when anchor stride mismatches") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = fs::temp_directory_path() / "w1rewind_index_stride.trace";
  fs::path index_path = fs::temp_directory_path() / "w1rewind_index_stride.trace.w1ridx";

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header();
  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1rewind.index"));

  write_basic_metadata(handle.builder, "x86_64", arch, minimal_registers(arch));
  w1::rewind::thread_start_record start{};
  start.thread_id = 1;
  start.name = "thread1";
  REQUIRE(handle.builder.emit_thread_start(start));

  write_instruction_range(handle.builder, 1, 0, 12, 0x1000);

  w1::rewind::thread_end_record end{};
  end.thread_id = 1;
  REQUIRE(handle.builder.emit_thread_end(end));

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_index_options build_options;
  build_options.anchor_stride = 5;

  w1::rewind::trace_index initial;
  REQUIRE(
      w1::rewind::build_trace_index(
          trace_path.string(), index_path.string(), build_options, &initial, redlog::get_logger("test.w1rewind.index")
      )
  );

  w1::rewind::trace_index_options ensure_options;
  ensure_options.anchor_stride = 2;

  w1::rewind::trace_index rebuilt;
  std::string ensure_error;
  REQUIRE(w1::rewind::ensure_trace_index(trace_path, index_path, ensure_options, rebuilt, ensure_error));
  CHECK(rebuilt.header.anchor_stride == 2);
}

TEST_CASE("w1rewind trace index is empty when no flow records exist") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = fs::temp_directory_path() / "w1rewind_index_empty.trace";
  fs::path index_path = fs::temp_directory_path() / "w1rewind_index_empty.trace.w1ridx";

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header();
  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1rewind.index"));

  write_basic_metadata(handle.builder, "x86_64", arch, minimal_registers(arch));
  write_thread_start(handle.builder, 1, "thread1");
  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_index index;
  w1::rewind::trace_index_options options;
  REQUIRE(
      w1::rewind::build_trace_index(
          trace_path.string(), index_path.string(), options, &index, redlog::get_logger("test.w1rewind.index")
      )
  );

  CHECK(index.threads.empty());
  CHECK(index.anchors.empty());
  CHECK(index.header.thread_count == 0);

  fs::remove(trace_path);
  fs::remove(index_path);
}
