#include <filesystem>
#include <memory>
#include <string>

#include "doctest/doctest.hpp"

#include "w1rewind/rewind_test_helpers.hpp"
#include "w1rewind/replay/flow_cursor.hpp"
#include "w1rewind/replay/replay_context.hpp"
#include "w1rewind/replay/replay_instruction_cursor.hpp"
#include "w1rewind/replay/replay_state.hpp"
#include "w1rewind/replay/replay_state_applier.hpp"
#include "w1rewind/replay/stateful_flow_cursor.hpp"
#include "w1rewind/trace/trace_index.hpp"
#include "w1rewind/trace/trace_reader.hpp"

namespace {

class test_block_decoder final : public w1::rewind::block_decoder {
public:
  bool decode_block(
      const w1::rewind::replay_context&, const w1::rewind::flow_step& flow, w1::rewind::decoded_block& out, std::string&
  ) override {
    uint64_t address = flow.address;
    uint32_t size = flow.size;
    if (size == 0 || (size % 2) != 0) {
      return false;
    }

    out.start = address;
    out.size = size;

    uint32_t offset = 0;
    while (offset < size) {
      w1::rewind::decoded_instruction inst{};
      inst.address = address + offset;
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
  fs::path index_path = temp_path("w1rewind_replay_instruction_cursor.trace.w1ridx");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header(0, 64);
  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1rewind.replay.instruction_cursor"));

  write_basic_metadata(handle.builder, "x86_64", arch, minimal_registers(arch));
  write_image_mapping(handle.builder, 1, 0x2000, 0x1000);
  write_thread_start(handle.builder, 1, "thread1");
  write_block_def(handle.builder, 1, 0x2000 + 0x20, 4);
  write_block_exec(handle.builder, 1, 0, 1);
  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_index_options index_options;
  w1::rewind::trace_index index;
  REQUIRE(
      w1::rewind::build_trace_index(
          trace_path.string(), index_path.string(), index_options, &index,
          redlog::get_logger("test.w1rewind.replay.instruction_cursor")
      )
  );

  auto index_ptr = std::make_shared<w1::rewind::trace_index>(index);

  w1::rewind::replay_context context;
  std::string error;
  REQUIRE(w1::rewind::load_replay_context(trace_path.string(), context, error));

  auto stream = std::make_shared<w1::rewind::trace_reader>(trace_path.string());
  w1::rewind::record_stream_cursor stream_cursor(stream);
  w1::rewind::flow_extractor extractor(&context);
  w1::rewind::history_window history(4);
  w1::rewind::flow_cursor flow_cursor(std::move(stream_cursor), std::move(extractor), std::move(history), index_ptr);
  REQUIRE(flow_cursor.open());

  w1::rewind::replay_state state;
  w1::rewind::replay_state_applier applier(context);
  w1::rewind::stateful_flow_cursor stateful_cursor(flow_cursor, applier, state);
  REQUIRE(stateful_cursor.configure(context, false, false, nullptr));
  REQUIRE(flow_cursor.seek(1, 0));

  test_block_decoder decoder;
  w1::rewind::replay_instruction_cursor instruction_cursor(stateful_cursor);
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
  fs::path index_path = temp_path("w1rewind_replay_instruction_cursor_notice.trace.w1ridx");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header(0, 64);
  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1rewind.replay.instruction_cursor"));

  write_basic_metadata(handle.builder, "x86_64", arch, minimal_registers(arch));
  write_image_mapping(handle.builder, 2, 0x4000, 0x1000);
  write_thread_start(handle.builder, 1, "thread1");
  write_block_def(handle.builder, 1, 0x4000 + 0x10, 4);
  write_block_exec(handle.builder, 1, 0, 1);
  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_index_options index_options;
  w1::rewind::trace_index index;
  REQUIRE(
      w1::rewind::build_trace_index(
          trace_path.string(), index_path.string(), index_options, &index,
          redlog::get_logger("test.w1rewind.replay.instruction_cursor")
      )
  );

  auto index_ptr = std::make_shared<w1::rewind::trace_index>(index);

  w1::rewind::replay_context context;
  std::string error;
  REQUIRE(w1::rewind::load_replay_context(trace_path.string(), context, error));

  auto stream = std::make_shared<w1::rewind::trace_reader>(trace_path.string());
  w1::rewind::record_stream_cursor stream_cursor(stream);
  w1::rewind::flow_extractor extractor(&context);
  w1::rewind::history_window history(4);
  w1::rewind::flow_cursor flow_cursor(std::move(stream_cursor), std::move(extractor), std::move(history), index_ptr);
  REQUIRE(flow_cursor.open());

  w1::rewind::replay_state state;
  w1::rewind::replay_state_applier applier(context);
  w1::rewind::stateful_flow_cursor stateful_cursor(flow_cursor, applier, state);
  REQUIRE(stateful_cursor.configure(context, false, false, nullptr));
  REQUIRE(flow_cursor.seek(1, 0));

  w1::rewind::replay_instruction_cursor instruction_cursor(stateful_cursor);

  w1::rewind::flow_step step{};
  REQUIRE(instruction_cursor.step_forward(step));
  CHECK(step.is_block);

  auto notice = instruction_cursor.take_notice();
  REQUIRE(notice.has_value());
  CHECK(notice->kind == w1::rewind::replay_notice_kind::decode_unavailable);
}

TEST_CASE("w1rewind replay instruction cursor fails in strict mode when decoder is missing") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_instruction_cursor_strict.trace");
  fs::path index_path = temp_path("w1rewind_replay_instruction_cursor_strict.trace.w1ridx");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header(0, 64);
  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1rewind.replay.instruction_cursor"));

  write_basic_metadata(handle.builder, "x86_64", arch, minimal_registers(arch));
  write_image_mapping(handle.builder, 3, 0x5000, 0x1000);
  write_thread_start(handle.builder, 1, "thread1");
  write_block_def(handle.builder, 1, 0x5000 + 0x10, 4);
  write_block_exec(handle.builder, 1, 0, 1);
  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_index_options index_options;
  w1::rewind::trace_index index;
  REQUIRE(
      w1::rewind::build_trace_index(
          trace_path.string(), index_path.string(), index_options, &index,
          redlog::get_logger("test.w1rewind.replay.instruction_cursor")
      )
  );

  auto index_ptr = std::make_shared<w1::rewind::trace_index>(index);

  w1::rewind::replay_context context;
  std::string error;
  REQUIRE(w1::rewind::load_replay_context(trace_path.string(), context, error));

  auto stream = std::make_shared<w1::rewind::trace_reader>(trace_path.string());
  w1::rewind::record_stream_cursor stream_cursor(stream);
  w1::rewind::flow_extractor extractor(&context);
  w1::rewind::history_window history(4);
  w1::rewind::flow_cursor flow_cursor(std::move(stream_cursor), std::move(extractor), std::move(history), index_ptr);
  REQUIRE(flow_cursor.open());

  w1::rewind::replay_state state;
  w1::rewind::replay_state_applier applier(context);
  w1::rewind::stateful_flow_cursor stateful_cursor(flow_cursor, applier, state);
  REQUIRE(stateful_cursor.configure(context, false, false, nullptr));
  REQUIRE(flow_cursor.seek(1, 0));

  w1::rewind::replay_instruction_cursor instruction_cursor(stateful_cursor);
  instruction_cursor.set_strict(true);

  w1::rewind::flow_step step{};
  CHECK_FALSE(instruction_cursor.step_forward(step));
  CHECK(instruction_cursor.error() == "block decoder unavailable");
}
