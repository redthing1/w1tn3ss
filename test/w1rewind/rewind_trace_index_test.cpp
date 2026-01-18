#include <filesystem>

#include "doctest/doctest.hpp"

#include "w1rewind/rewind_test_helpers.hpp"
#include "w1rewind/replay/trace_index.hpp"
#include "w1rewind/replay/trace_reader.hpp"
#include "w1rewind/record/trace_writer.hpp"

namespace {

void write_instruction_range(
    w1::rewind::trace_writer& writer,
    uint64_t thread_id,
    uint64_t start_seq,
    uint64_t count,
    uint64_t module_id
) {
  for (uint64_t i = 0; i < count; ++i) {
    w1::rewind::instruction_record record{};
    record.sequence = start_seq + i;
    record.thread_id = thread_id;
    record.module_id = module_id;
    record.module_offset = 0x100 + i * 4;
    record.size = 4;
    record.flags = 0;
    REQUIRE(writer.write_instruction(record));
  }
}

} // namespace

TEST_CASE("w1rewind trace index builds anchors for instruction flow") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = fs::temp_directory_path() / "w1rewind_index.trace";
  fs::path index_path = fs::temp_directory_path() / "w1rewind_index.trace.idx";

  w1::rewind::trace_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1rewind.index");

  auto writer = w1::rewind::make_trace_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1::rewind::trace_header header{};
  header.architecture = w1::rewind::detect_trace_arch();
  header.pointer_size = w1::rewind::detect_pointer_size();
  header.flags = w1::rewind::trace_flag_instructions;
  REQUIRE(writer->write_header(header));

  write_basic_metadata(*writer, header.architecture, header.pointer_size, minimal_registers(header.architecture));
  w1::rewind::thread_start_record start1{};
  start1.thread_id = 1;
  start1.name = "thread1";
  REQUIRE(writer->write_thread_start(start1));

  w1::rewind::thread_start_record start2{};
  start2.thread_id = 2;
  start2.name = "thread2";
  REQUIRE(writer->write_thread_start(start2));

  write_instruction_range(*writer, 1, 0, 10, 1);
  write_instruction_range(*writer, 2, 0, 5, 2);

  w1::rewind::thread_end_record end1{};
  end1.thread_id = 1;
  REQUIRE(writer->write_thread_end(end1));

  w1::rewind::thread_end_record end2{};
  end2.thread_id = 2;
  REQUIRE(writer->write_thread_end(end2));

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options options;
  options.anchor_stride = 3;
  options.include_snapshots = false;

  w1::rewind::trace_index index;
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), options, &index, writer_config.log));

  w1::rewind::trace_index loaded;
  REQUIRE(w1::rewind::load_trace_index(index_path.string(), loaded, writer_config.log));

  CHECK(loaded.header.trace_flags == header.flags);
  CHECK(!loaded.chunks.empty());
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
