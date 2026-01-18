#include <filesystem>

#include "doctest/doctest.hpp"

#include "w1rewind/rewind_test_helpers.hpp"
#include "w1rewind/replay/trace_cursor.hpp"
#include "w1rewind/replay/trace_index.hpp"
#include "w1rewind/record/trace_writer.hpp"

namespace {

void write_instruction_local(
    w1::rewind::trace_writer& writer,
    uint64_t thread_id,
    uint64_t sequence,
    uint64_t address
) {
  w1::rewind::instruction_record record{};
  record.sequence = sequence;
  record.thread_id = thread_id;
  record.address = address;
  record.size = 4;
  record.flags = 0;
  REQUIRE(writer.write_instruction(record));
}

} // namespace

TEST_CASE("w1rewind trace cursor seeks to a flow sequence") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = fs::temp_directory_path() / "w1rewind_cursor.trace";
  fs::path index_path = fs::temp_directory_path() / "w1rewind_cursor.trace.idx";

  w1::rewind::trace_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1rewind.cursor");
  writer_config.chunk_size = 64;

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

  for (uint64_t i = 0; i < 8; ++i) {
    write_instruction_local(*writer, 1, i, 0x100 + i * 4);
    if (i < 4) {
      write_instruction_local(*writer, 2, i, 0x200 + i * 4);
    }
  }

  w1::rewind::thread_end_record end1{};
  end1.thread_id = 1;
  REQUIRE(writer->write_thread_end(end1));

  w1::rewind::thread_end_record end2{};
  end2.thread_id = 2;
  REQUIRE(writer->write_thread_end(end2));

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options options;
  options.anchor_stride = 2;
  options.include_snapshots = false;

  w1::rewind::trace_index index;
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), options, &index, writer_config.log));

  w1::rewind::trace_cursor cursor({trace_path.string(), index_path.string()});
  REQUIRE(cursor.open());
  REQUIRE(cursor.load_index());
  REQUIRE(cursor.seek_flow(2, 3));

  w1::rewind::trace_record record;
  REQUIRE(cursor.read_next(record));
  REQUIRE(std::holds_alternative<w1::rewind::instruction_record>(record));
  const auto& inst = std::get<w1::rewind::instruction_record>(record);
  CHECK(inst.thread_id == 2);
  CHECK(inst.sequence == 3);

  w1::rewind::trace_record next;
  REQUIRE(cursor.read_next(next));
  REQUIRE(std::holds_alternative<w1::rewind::instruction_record>(next));
  const auto& next_inst = std::get<w1::rewind::instruction_record>(next);
  CHECK(next_inst.thread_id == 1);
  CHECK(next_inst.sequence == 4);
}
