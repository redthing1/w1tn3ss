#include <filesystem>

#include "doctest/doctest.hpp"

#include "rewind_test_helpers.hpp"
#include "w1tn3ss/runtime/rewind/replay_instruction_cursor.hpp"
#include "w1tn3ss/runtime/rewind/trace_index.hpp"
#include "w1tn3ss/runtime/rewind/trace_writer.hpp"

namespace {

class test_block_decoder final : public w1::rewind::replay_block_decoder {
public:
  bool decode_block(
      const w1::rewind::replay_context&,
      uint64_t module_id,
      uint64_t module_offset,
      uint32_t size,
      w1::rewind::replay_decoded_block& out,
      std::string&
  ) override {
    if (size == 0 || (size % 2) != 0) {
      return false;
    }

    out.module_id = module_id;
    out.module_offset = module_offset;
    out.size = size;

    uint32_t offset = 0;
    while (offset < size) {
      w1::rewind::replay_decoded_instruction inst{};
      inst.offset = offset;
      inst.size = 2;
      inst.bytes = {0x90, 0x90};
      out.instructions.push_back(inst);
      offset += 2;
    }

    return true;
  }
};

} // namespace

TEST_CASE("w1rewind replay instruction cursor decodes blocks and steps backward") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_instruction_cursor.trace");
  fs::path index_path = temp_path("w1rewind_replay_instruction_cursor.trace.idx");

  w1::rewind::trace_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1rewind.replay.instruction_cursor");
  writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1::rewind::trace_header header{};
  header.flags = w1::rewind::trace_flag_blocks;
  REQUIRE(writer->write_header(header));

  write_module_table(*writer, 1, 0x2000);
  write_thread_start(*writer, 1, "thread1");
  write_block_def(*writer, 1, 1, 0x20, 4);
  write_block_exec(*writer, 1, 0, 1);
  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  w1::rewind::trace_index index;
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, &index, writer_config.log));

  w1::rewind::replay_flow_cursor_config replay_config{};
  replay_config.trace_path = trace_path.string();
  replay_config.index_path = index_path.string();
  replay_config.history_size = 4;
  replay_config.track_registers = false;
  replay_config.track_memory = false;

  w1::rewind::replay_flow_cursor flow_cursor(replay_config);
  REQUIRE(flow_cursor.open());
  REQUIRE(flow_cursor.seek(1, 0));

  test_block_decoder decoder;
  w1::rewind::replay_instruction_cursor instruction_cursor(flow_cursor);
  instruction_cursor.set_decoder(&decoder);

  w1::rewind::flow_step step{};
  REQUIRE(instruction_cursor.step_forward(step));
  CHECK(step.address == 0x2000 + 0x20);

  REQUIRE(instruction_cursor.step_forward(step));
  CHECK(step.address == 0x2000 + 0x22);

  REQUIRE(instruction_cursor.step_backward(step));
  CHECK(step.address == 0x2000 + 0x20);
}

TEST_CASE("w1rewind replay instruction cursor reports missing decoder") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_instruction_cursor_notice.trace");
  fs::path index_path = temp_path("w1rewind_replay_instruction_cursor_notice.trace.idx");

  w1::rewind::trace_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1rewind.replay.instruction_cursor");
  writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1::rewind::trace_header header{};
  header.flags = w1::rewind::trace_flag_blocks;
  REQUIRE(writer->write_header(header));

  write_module_table(*writer, 2, 0x4000);
  write_thread_start(*writer, 1, "thread1");
  write_block_def(*writer, 1, 2, 0x10, 4);
  write_block_exec(*writer, 1, 0, 1);
  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  w1::rewind::trace_index index;
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, &index, writer_config.log));

  w1::rewind::replay_flow_cursor_config replay_config{};
  replay_config.trace_path = trace_path.string();
  replay_config.index_path = index_path.string();
  replay_config.history_size = 4;
  replay_config.track_registers = false;
  replay_config.track_memory = false;

  w1::rewind::replay_flow_cursor flow_cursor(replay_config);
  REQUIRE(flow_cursor.open());
  REQUIRE(flow_cursor.seek(1, 0));

  w1::rewind::replay_instruction_cursor instruction_cursor(flow_cursor);

  w1::rewind::flow_step step{};
  REQUIRE(instruction_cursor.step_forward(step));
  CHECK(step.is_block);

  auto notice = instruction_cursor.take_notice();
  REQUIRE(notice.has_value());
  CHECK(notice->kind == w1::rewind::replay_notice_kind::decode_unavailable);
}
