#include "doctest/doctest.hpp"

#include "w1rewind/rewind_test_helpers.hpp"
#include "w1rewind/replay/replay_session.hpp"
#include "w1rewind/trace/trace_index.hpp"
#include "w1rewind/trace/trace_reader.hpp"

namespace {

class test_block_decoder final : public w1::rewind::block_decoder {
public:
  bool decode_block(
      const w1::rewind::replay_context&, const w1::rewind::flow_step& flow, w1::rewind::decoded_block& out,
      std::string&
  ) override {
    out.start = flow.address;
    out.size = flow.size;
    out.instructions.clear();

    w1::rewind::decoded_instruction first{};
    first.address = flow.address;
    first.size = 2;
    w1::rewind::decoded_instruction second{};
    second.address = flow.address + 2;
    second.size = 2;
    out.instructions.push_back(first);
    out.instructions.push_back(second);
    return true;
  }
};

} // namespace

TEST_CASE("w1rewind replay session normalizes to instruction start/end") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_session_pos.trace");
  fs::path index_path = temp_path("w1rewind_replay_session_pos.trace.w1ridx");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header(0, 64);
  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1rewind.replay.session_position"));

  write_basic_metadata(handle.builder, "x86_64", arch, minimal_registers(arch));
  write_image_mapping(handle.builder, 1, 0x2000, 0x1000);
  write_thread_start(handle.builder, 1, "thread1");
  write_block_def(handle.builder, 1, 0x2000 + 0x20, 4);
  write_block_exec(handle.builder, 1, 0, 1);
  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_index_options index_options;
  auto index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(
      w1::rewind::build_trace_index(
          trace_path.string(), index_path.string(), index_options, index.get(),
          redlog::get_logger("test.w1rewind.replay.session_position")
      )
  );

  w1::rewind::replay_context context;
  std::string error;
  REQUIRE(w1::rewind::load_replay_context(trace_path.string(), context, error));

  test_block_decoder decoder;
  w1::rewind::replay_session_config config;
  config.stream = std::make_shared<w1::rewind::trace_reader>(trace_path.string());
  config.index = index;
  config.context = context;
  config.block_decoder = &decoder;

  w1::rewind::replay_session session(config);
  REQUIRE(session.open());
  REQUIRE(session.select_thread(1, 0));
  REQUIRE(session.step_flow());

  REQUIRE(session.sync_instruction_position(true));
  CHECK(session.current_step().address == 0x2000 + 0x20);
  CHECK_FALSE(session.current_step().is_block);

  REQUIRE(session.select_thread(1, 0));
  REQUIRE(session.step_flow());
  REQUIRE(session.sync_instruction_position(false));
  CHECK(session.current_step().address == 0x2000 + 0x22);
  CHECK_FALSE(session.current_step().is_block);
}
