#include <chrono>
#include <filesystem>
#include <limits>
#include <memory>
#include <string>

#include "doctest/doctest.hpp"

#include "w1rewind/rewind_test_helpers.hpp"
#include "w1rewind/replay/block_decoder.hpp"
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
    if (flow.size == 0 || (flow.size % 2) != 0) {
      return false;
    }

    out.start = flow.address;
    out.size = flow.size;

    uint32_t offset = 0;
    while (offset < flow.size) {
      w1::rewind::decoded_instruction inst{};
      inst.address = flow.address + offset;
      inst.size = 2;
      inst.bytes = {0x90, 0x90};
      out.instructions.push_back(inst);
      offset += 2;
    }

    return true;
  }
};

w1::rewind::file_header make_uuid_header(uint8_t id, uint32_t chunk_size) {
  auto header = w1::rewind::test_helpers::make_header(0, chunk_size);
  header.trace_uuid[0] = id;
  return header;
}

} // namespace

TEST_CASE("w1rewind replay session steps through decoded block instructions") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_session_block.trace");
  fs::path index_path = temp_path("w1rewind_replay_session_block.trace.w1ridx");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header(0, 64);
  auto logger = redlog::get_logger("test.w1rewind.replay.session");
  auto handle = open_trace(trace_path, header, logger);

  write_basic_metadata(handle.builder, "x86_64", arch, minimal_registers(arch));
  write_image_mapping(handle.builder, 7, 0x2000, 0x1000);

  write_thread_start(handle.builder, 1, "thread1");
  write_block_def(handle.builder, 1, 0x2000 + 0x20, 4);
  write_block_def(handle.builder, 2, 0x2000 + 0x40, 4);
  write_block_exec(handle.builder, 1, 0, 1);
  write_block_exec(handle.builder, 1, 1, 2);
  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_index_options index_options;
  index_options.anchor_stride = 1;
  auto index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, index.get(), logger));

  w1::rewind::replay_context context;
  std::string context_error;
  REQUIRE(w1::rewind::load_replay_context(trace_path.string(), context, context_error));

  auto stream = std::make_shared<w1::rewind::trace_reader>(trace_path.string());

  test_block_decoder decoder;
  w1::rewind::replay_session_config config{};
  config.stream = stream;
  config.index = index;
  config.context = context;
  config.thread_id = 1;
  config.track_registers = false;
  config.track_memory = false;
  config.block_decoder = &decoder;

  w1::rewind::replay_session session(config);
  REQUIRE(session.open());

  REQUIRE(session.step_instruction());
  auto step = session.current_step();
  CHECK(!step.is_block);
  CHECK(step.sequence == 0);
  CHECK(step.address == 0x2000 + 0x20);

  REQUIRE(session.step_instruction());
  step = session.current_step();
  CHECK(step.address == 0x2000 + 0x22);

  REQUIRE(session.step_instruction());
  step = session.current_step();
  CHECK(step.sequence == 1);
  CHECK(step.address == 0x2000 + 0x40);

  REQUIRE(session.step_instruction());
  step = session.current_step();
  CHECK(step.address == 0x2000 + 0x42);
}

TEST_CASE("w1rewind replay session instruction stepping falls back without decoder") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_session_fallback.trace");
  fs::path index_path = temp_path("w1rewind_replay_session_fallback.trace.w1ridx");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header(0, 64);
  auto logger = redlog::get_logger("test.w1rewind.replay.session");
  auto handle = open_trace(trace_path, header, logger);

  write_basic_metadata(handle.builder, "x86_64", arch, minimal_registers(arch));
  write_image_mapping(handle.builder, 9, 0x3000, 0x1000);
  write_thread_start(handle.builder, 1, "thread1");
  write_block_def(handle.builder, 1, 0x3000 + 0x10, 4);
  write_block_exec(handle.builder, 1, 0, 1);
  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_index_options index_options;
  index_options.anchor_stride = 1;
  auto index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, index.get(), logger));

  w1::rewind::replay_context context;
  std::string context_error;
  REQUIRE(w1::rewind::load_replay_context(trace_path.string(), context, context_error));

  auto stream = std::make_shared<w1::rewind::trace_reader>(trace_path.string());

  w1::rewind::replay_session_config config{};
  config.stream = stream;
  config.index = index;
  config.context = context;
  config.thread_id = 1;
  config.track_registers = false;
  config.track_memory = false;

  w1::rewind::replay_session session(config);
  REQUIRE(session.open());

  REQUIRE(session.step_instruction());
  auto step = session.current_step();
  CHECK(step.is_block);
  CHECK(step.sequence == 0);
  CHECK(step.address == 0x3000 + 0x10);
}

TEST_CASE("w1rewind trace index rebuilds stale index when trace changes") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_session_rebuild.trace");
  fs::path index_path = temp_path("w1rewind_replay_session_rebuild.trace.w1ridx");

  auto arch = parse_arch_or_fail("x86_64");
  auto logger = redlog::get_logger("test.w1rewind.replay.session");

  auto header = make_header(0, 64);
  auto handle = open_trace(trace_path, header, logger);
  write_basic_metadata(handle.builder, "x86_64", arch, minimal_registers(arch));
  write_image_mapping(handle.builder, 5, 0x1000, 0x1000);
  write_thread_start(handle.builder, 1, "thread1");
  write_block_def(handle.builder, 1, 0x1000 + 0x10, 4);
  write_block_exec(handle.builder, 1, 0, 1);
  write_thread_end(handle.builder, 1);
  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_index_options index_options;
  index_options.anchor_stride = 1;
  auto index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, index.get(), logger));

  auto new_handle = open_trace(trace_path, header, logger);
  write_basic_metadata(new_handle.builder, "x86_64", arch, minimal_registers(arch));
  write_image_mapping(new_handle.builder, 5, 0x1000, 0x1000);
  write_thread_start(new_handle.builder, 1, "thread1");
  write_block_def(new_handle.builder, 1, 0x1000 + 0x20, 4);
  write_block_exec(new_handle.builder, 1, 0, 1);
  write_block_def(new_handle.builder, 2, 0x1000 + 0x40, 4);
  write_block_exec(new_handle.builder, 1, 1, 2);
  write_thread_end(new_handle.builder, 1);
  new_handle.builder.flush();
  new_handle.writer->close();

  auto new_time = fs::file_time_type::clock::now() + std::chrono::seconds(2);
  std::error_code time_error;
  fs::last_write_time(trace_path, new_time, time_error);
  REQUIRE(!time_error);

  w1::rewind::trace_index rebuilt;
  std::string ensure_error;
  REQUIRE(w1::rewind::ensure_trace_index(trace_path, index_path, index_options, rebuilt, ensure_error));
  CHECK(rebuilt.anchors.size() == 2);
}

TEST_CASE("w1rewind trace index rebuilds index on mismatch even if trace is older") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_session_rebuild_mismatch.trace");
  fs::path index_path = temp_path("w1rewind_replay_session_rebuild_mismatch.trace.w1ridx");

  auto arch = parse_arch_or_fail("x86_64");
  auto logger = redlog::get_logger("test.w1rewind.replay.session");

  auto header = make_uuid_header(1, 64);
  auto handle = open_trace(trace_path, header, logger);
  write_basic_metadata(handle.builder, "x86_64", arch, minimal_registers(arch));
  write_image_mapping(handle.builder, 6, 0x1000, 0x1000);
  write_thread_start(handle.builder, 1, "thread1");
  write_block_def(handle.builder, 1, 0x1000 + 0x10, 4);
  write_block_exec(handle.builder, 1, 0, 1);
  write_thread_end(handle.builder, 1);
  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_index_options index_options;
  auto index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, index.get(), logger));

  auto index_time = fs::last_write_time(index_path);

  auto new_header = make_uuid_header(2, 64);
  auto new_handle = open_trace(trace_path, new_header, logger);
  write_basic_metadata(new_handle.builder, "x86_64", arch, minimal_registers(arch));
  write_image_mapping(new_handle.builder, 6, 0x1000, 0x1000);
  write_thread_start(new_handle.builder, 1, "thread1");
  write_block_def(new_handle.builder, 1, 0x1000 + 0x20, 4);
  write_block_exec(new_handle.builder, 1, 0, 1);
  write_thread_end(new_handle.builder, 1);
  new_handle.builder.flush();
  new_handle.writer->close();

  std::error_code time_error;
  fs::last_write_time(trace_path, index_time - std::chrono::seconds(2), time_error);
  REQUIRE(!time_error);

  w1::rewind::trace_index rebuilt;
  std::string ensure_error;
  REQUIRE(w1::rewind::ensure_trace_index(trace_path, index_path, index_options, rebuilt, ensure_error));
  CHECK(rebuilt.header.trace_uuid[0] == 2);
}

TEST_CASE("w1rewind replay session supports reverse instruction stepping on block traces") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_session_reverse.trace");
  fs::path index_path = temp_path("w1rewind_replay_session_reverse.trace.w1ridx");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header(0, 64);
  auto logger = redlog::get_logger("test.w1rewind.replay.session");
  auto handle = open_trace(trace_path, header, logger);

  write_basic_metadata(handle.builder, "x86_64", arch, minimal_registers(arch));
  write_image_mapping(handle.builder, 11, 0x5000, 0x1000);
  write_thread_start(handle.builder, 1, "thread1");
  write_block_def(handle.builder, 1, 0x5000 + 0x20, 4);
  write_block_exec(handle.builder, 1, 0, 1);
  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_index_options index_options;
  auto index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, index.get(), logger));

  w1::rewind::replay_context context;
  std::string context_error;
  REQUIRE(w1::rewind::load_replay_context(trace_path.string(), context, context_error));

  auto stream = std::make_shared<w1::rewind::trace_reader>(trace_path.string());

  test_block_decoder decoder;
  w1::rewind::replay_session_config config{};
  config.stream = stream;
  config.index = index;
  config.context = context;
  config.thread_id = 1;
  config.track_registers = false;
  config.track_memory = false;
  config.block_decoder = &decoder;

  w1::rewind::replay_session session(config);
  REQUIRE(session.open());

  REQUIRE(session.step_flow());
  auto flow = session.current_step();
  CHECK(flow.is_block);

  REQUIRE(session.step_instruction_backward());
  auto step = session.current_step();
  CHECK(step.sequence == 0);
  CHECK(step.address == 0x5000 + 0x22);

  REQUIRE(session.step_instruction_backward());
  step = session.current_step();
  CHECK(step.address == 0x5000 + 0x20);
}

TEST_CASE("w1rewind replay session preserves state across intra-block steps") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_session_state.trace");
  fs::path index_path = temp_path("w1rewind_replay_session_state.trace.w1ridx");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header(0, 64);
  auto logger = redlog::get_logger("test.w1rewind.replay.session");
  auto handle = open_trace(trace_path, header, logger);

  write_basic_metadata(handle.builder, "x86_64", arch, {"r0"});
  write_image_mapping(handle.builder, 12, 0x6000, 0x1000);

  write_thread_start(handle.builder, 1, "thread1");
  write_block_def(handle.builder, 1, 0x6000 + 0x20, 4);
  write_block_def(handle.builder, 2, 0x6000 + 0x40, 4);
  write_block_exec(handle.builder, 1, 0, 1);
  write_register_delta(handle.builder, 1, 0, 0, 0x1000);
  write_block_exec(handle.builder, 1, 1, 2);
  write_register_delta(handle.builder, 1, 1, 0, 0x1001);
  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_index_options index_options;
  auto index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, index.get(), logger));

  w1::rewind::replay_context context;
  std::string context_error;
  REQUIRE(w1::rewind::load_replay_context(trace_path.string(), context, context_error));

  auto stream = std::make_shared<w1::rewind::trace_reader>(trace_path.string());

  test_block_decoder decoder;
  w1::rewind::replay_session_config config{};
  config.stream = stream;
  config.index = index;
  config.context = context;
  config.thread_id = 1;
  config.track_registers = true;
  config.track_memory = false;
  config.block_decoder = &decoder;

  w1::rewind::replay_session session(config);
  REQUIRE(session.open());

  REQUIRE(session.step_instruction());
  auto regs = session.read_registers();
  REQUIRE(regs.size() >= 1);
  CHECK(regs[0].has_value());
  CHECK(regs[0].value() == 0x1000);

  REQUIRE(session.step_instruction());
  regs = session.read_registers();
  CHECK(regs[0].has_value());
  CHECK(regs[0].value() == 0x1000);

  REQUIRE(session.step_instruction());
  regs = session.read_registers();
  CHECK(regs[0].has_value());
  CHECK(regs[0].value() == 0x1001);

  REQUIRE(session.step_instruction_backward());
  regs = session.read_registers();
  CHECK(regs[0].has_value());
  CHECK(regs[0].value() == 0x1000);
}

TEST_CASE("w1rewind replay session reverse instruction stepping on instruction traces") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_session_reverse_inst.trace");
  fs::path index_path = temp_path("w1rewind_replay_session_reverse_inst.trace.w1ridx");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header(0, 64);
  auto logger = redlog::get_logger("test.w1rewind.replay.session");
  auto handle = open_trace(trace_path, header, logger);

  write_basic_metadata(handle.builder, "x86_64", arch, {"r0"});
  write_image_mapping(handle.builder, 13, 0x7000, 0x1000);

  write_thread_start(handle.builder, 1, "thread1");

  for (uint64_t seq = 0; seq < 3; ++seq) {
    write_instruction(handle.builder, 1, seq, 0x7000 + 0x10 + seq * 4);
    write_register_delta(handle.builder, 1, seq, 0, 0x2000 + seq);
  }

  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_index_options index_options;
  auto index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, index.get(), logger));

  w1::rewind::replay_context context;
  std::string context_error;
  REQUIRE(w1::rewind::load_replay_context(trace_path.string(), context, context_error));

  auto stream = std::make_shared<w1::rewind::trace_reader>(trace_path.string());

  w1::rewind::replay_session_config config{};
  config.stream = stream;
  config.index = index;
  config.context = context;
  config.thread_id = 1;
  config.track_registers = true;
  config.track_memory = false;

  w1::rewind::replay_session session(config);
  REQUIRE(session.open());

  REQUIRE(session.step_flow());
  auto step = session.current_step();
  CHECK(!step.is_block);
  CHECK(step.sequence == 0);
  auto regs = session.read_registers();
  CHECK(regs[0].has_value());
  CHECK(regs[0].value() == 0x2000);

  REQUIRE(session.step_flow());
  step = session.current_step();
  CHECK(step.sequence == 1);
  regs = session.read_registers();
  CHECK(regs[0].has_value());
  CHECK(regs[0].value() == 0x2001);

  REQUIRE(session.step_instruction_backward());
  step = session.current_step();
  CHECK(step.sequence == 0);
  regs = session.read_registers();
  CHECK(regs[0].has_value());
  CHECK(regs[0].value() == 0x2000);
}

TEST_CASE("w1rewind replay session rejects invalid mapping snapshots") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_session_bad_mapping.trace");
  fs::path index_path = temp_path("w1rewind_replay_session_bad_mapping.trace.w1ridx");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header(0, 64);
  auto logger = redlog::get_logger("test.w1rewind.replay.session");
  auto handle = open_trace(trace_path, header, logger);
  write_basic_metadata(handle.builder, "x86_64", arch, minimal_registers(arch));
  write_thread_start(handle.builder, 1, "thread1");
  write_block_def(handle.builder, 1, 0x1000, 4);
  write_block_exec(handle.builder, 1, 0, 1);
  write_thread_end(handle.builder, 1);
  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_index_options index_options;
  index_options.anchor_stride = 1;
  auto index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, index.get(), logger));

  w1::rewind::replay_context context;
  std::string context_error;
  REQUIRE(w1::rewind::load_replay_context(trace_path.string(), context, context_error));

  w1::rewind::mapping_record bad{};
  bad.kind = w1::rewind::mapping_event_kind::map;
  bad.space_id = 0;
  bad.base = std::numeric_limits<uint64_t>::max();
  bad.size = 1;
  context.mappings = {bad};

  auto stream = std::make_shared<w1::rewind::trace_reader>(trace_path.string());
  w1::rewind::replay_session_config config{};
  config.stream = stream;
  config.index = index;
  config.context = context;
  config.track_mappings = true;
  config.thread_id = 1;

  w1::rewind::replay_session session(config);
  CHECK_FALSE(session.open());
  CHECK(session.error() == "mapping range invalid");

  std::error_code ec;
  fs::remove(trace_path, ec);
  fs::remove(index_path, ec);
}
