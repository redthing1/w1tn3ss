#include <filesystem>
#include <memory>
#include <string>

#include "doctest/doctest.hpp"

#include <redlog.hpp>

#include "w1replay/gdb/stepper.hpp"
#include "w1rewind/replay/replay_context.hpp"
#include "w1rewind/replay/replay_session.hpp"
#include "w1rewind/trace/trace_index.hpp"
#include "w1rewind/trace/trace_reader.hpp"
#include "w1rewind/trace/trace_file_writer.hpp"

#include "w1rewind/rewind_test_helpers.hpp"

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

struct session_inputs {
  std::shared_ptr<w1::rewind::trace_reader> stream;
  std::shared_ptr<w1::rewind::trace_index> index;
  w1::rewind::replay_context context;
};

session_inputs build_session_inputs(const std::filesystem::path& trace_path) {
  session_inputs inputs;
  inputs.stream = std::make_shared<w1::rewind::trace_reader>(trace_path.string());

  std::string error;
  REQUIRE(w1::rewind::load_replay_context(trace_path.string(), inputs.context, error));

  w1::rewind::trace_index_options options;
  w1::rewind::trace_index index;
  error.clear();
  REQUIRE(w1::rewind::ensure_trace_index(trace_path, {}, options, index, error));
  inputs.index = std::make_shared<w1::rewind::trace_index>(std::move(index));
  return inputs;
}

std::filesystem::path write_block_trace(const char* name) {
  using namespace w1::rewind::test_helpers;
  namespace fs = std::filesystem;

  fs::path trace_path = temp_path(name);

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
  header.flags = w1::rewind::trace_flag_blocks;
  REQUIRE(writer->write_header(header));

  std::vector<std::string> registers = {"pc"};
  write_basic_metadata(*writer, arch, registers);
  write_module_table(*writer, 1, 0x1000);
  write_thread_start(*writer, 1, "thread1");

  write_block_def(*writer, 1, 0x1000 + 0x10, 4);
  write_block_def(*writer, 2, 0x1000 + 0x20, 4);
  write_block_exec(*writer, 1, 0, 1);
  write_block_exec(*writer, 1, 1, 2);

  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();
  return trace_path;
}

std::filesystem::path write_instruction_trace(const char* name) {
  using namespace w1::rewind::test_helpers;
  namespace fs = std::filesystem;

  fs::path trace_path = temp_path(name);

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

  std::vector<std::string> registers = {"pc"};
  write_basic_metadata(*writer, arch, registers);
  write_module_table(*writer, 1, 0x2000);
  write_thread_start(*writer, 1, "thread1");
  write_instruction(*writer, 1, 0, 0x2000 + 0x10);
  write_instruction(*writer, 1, 1, 0x2000 + 0x14);
  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();
  return trace_path;
}

} // namespace

TEST_CASE("gdb stepper uses instruction stepping when block decoder is available") {
  auto trace_path = write_block_trace("w1replay_gdb_stepper_block.trace");

  auto inputs = build_session_inputs(trace_path);

  test_block_decoder decoder;
  w1::rewind::replay_session_config session_config{};
  session_config.stream = inputs.stream;
  session_config.index = inputs.index;
  session_config.context = inputs.context;
  session_config.thread_id = 1;
  session_config.track_registers = false;
  session_config.track_memory = false;
  session_config.block_decoder = &decoder;

  w1::rewind::replay_session session(session_config);
  REQUIRE(session.open());

  w1replay::gdb::run_policy policy{};
  policy.trace_is_block = true;
  policy.decoder_available = true;

  auto result = w1replay::gdb::resume_step(session, policy, {}, 1, gdbstub::resume_direction::forward);
  CHECK(result.resume.state == gdbstub::resume_result::state::stopped);
  CHECK(session.current_step().address == 0x1010);
  CHECK(!session.current_step().is_block);
}

TEST_CASE("gdb stepper continues until breakpoint using instruction stepping") {
  auto trace_path = write_block_trace("w1replay_gdb_stepper_break.trace");

  auto inputs = build_session_inputs(trace_path);

  test_block_decoder decoder;
  w1::rewind::replay_session_config session_config{};
  session_config.stream = inputs.stream;
  session_config.index = inputs.index;
  session_config.context = inputs.context;
  session_config.thread_id = 1;
  session_config.track_registers = false;
  session_config.track_memory = false;
  session_config.block_decoder = &decoder;

  w1::rewind::replay_session session(session_config);
  REQUIRE(session.open());

  w1replay::gdb::run_policy policy{};
  policy.trace_is_block = true;
  policy.decoder_available = true;

  w1replay::gdb::breakpoint_store breakpoints;
  breakpoints.add(0x1020);
  auto result = w1replay::gdb::resume_continue(session, policy, breakpoints, 1, gdbstub::resume_direction::forward);
  CHECK(result.resume.stop.kind == gdbstub::stop_kind::sw_break);
  CHECK(result.resume.stop.addr == 0x1020);
  CHECK(session.current_step().address == 0x1020);
}

TEST_CASE("gdb stepper falls back to flow stepping without decoder") {
  auto trace_path = write_block_trace("w1replay_gdb_stepper_flow.trace");

  auto inputs = build_session_inputs(trace_path);

  w1::rewind::replay_session_config session_config{};
  session_config.stream = inputs.stream;
  session_config.index = inputs.index;
  session_config.context = inputs.context;
  session_config.thread_id = 1;
  session_config.track_registers = false;
  session_config.track_memory = false;

  w1::rewind::replay_session session(session_config);
  REQUIRE(session.open());

  w1replay::gdb::run_policy policy{};
  policy.trace_is_block = true;
  policy.decoder_available = false;

  auto result = w1replay::gdb::resume_step(session, policy, {}, 1, gdbstub::resume_direction::forward);
  CHECK(result.resume.state == gdbstub::resume_result::state::stopped);
  CHECK(session.current_step().address == 0x1010);
  CHECK(session.current_step().is_block);
}

TEST_CASE("gdb stepper uses flow stepping for instruction traces") {
  auto trace_path = write_instruction_trace("w1replay_gdb_stepper_inst.trace");

  auto inputs = build_session_inputs(trace_path);

  w1::rewind::replay_session_config session_config{};
  session_config.stream = inputs.stream;
  session_config.index = inputs.index;
  session_config.context = inputs.context;
  session_config.thread_id = 1;
  session_config.track_registers = false;
  session_config.track_memory = false;

  w1::rewind::replay_session session(session_config);
  REQUIRE(session.open());

  w1replay::gdb::run_policy policy{};
  policy.trace_is_block = false;
  policy.decoder_available = false;

  auto result = w1replay::gdb::resume_step(session, policy, {}, 1, gdbstub::resume_direction::forward);
  CHECK(result.resume.state == gdbstub::resume_result::state::stopped);
  CHECK(session.current_step().address == 0x2010);
  CHECK(!session.current_step().is_block);
}

TEST_CASE("gdb stepper reports replay-log end at forward trace boundary") {
  auto trace_path = write_instruction_trace("w1replay_gdb_stepper_end.trace");

  auto inputs = build_session_inputs(trace_path);

  w1::rewind::replay_session_config session_config{};
  session_config.stream = inputs.stream;
  session_config.index = inputs.index;
  session_config.context = inputs.context;
  session_config.thread_id = 1;
  session_config.track_registers = false;
  session_config.track_memory = false;

  w1::rewind::replay_session session(session_config);
  REQUIRE(session.open());

  w1replay::gdb::run_policy policy{};
  policy.trace_is_block = false;
  policy.decoder_available = false;

  auto result = w1replay::gdb::resume_continue(session, policy, {}, 1, gdbstub::resume_direction::forward);

  CHECK(result.resume.state == gdbstub::resume_result::state::stopped);
  REQUIRE(result.resume.stop.replay_log.has_value());
  CHECK(*result.resume.stop.replay_log == gdbstub::replay_log_boundary::end);
  CHECK(session.current_step().address == 0x2014);
}

TEST_CASE("gdb stepper supports reverse instruction stepping") {
  auto trace_path = write_block_trace("w1replay_gdb_stepper_reverse.trace");

  auto inputs = build_session_inputs(trace_path);

  test_block_decoder decoder;
  w1::rewind::replay_session_config session_config{};
  session_config.stream = inputs.stream;
  session_config.index = inputs.index;
  session_config.context = inputs.context;
  session_config.thread_id = 1;
  session_config.track_registers = false;
  session_config.track_memory = false;
  session_config.block_decoder = &decoder;

  w1::rewind::replay_session session(session_config);
  REQUIRE(session.open());

  REQUIRE(session.step_instruction());
  REQUIRE(session.step_instruction());
  CHECK(session.current_step().address == 0x1012);

  w1replay::gdb::run_policy policy{};
  policy.trace_is_block = true;
  policy.decoder_available = true;

  auto result = w1replay::gdb::resume_step(session, policy, {}, 1, gdbstub::resume_direction::reverse);

  CHECK(result.resume.state == gdbstub::resume_result::state::stopped);
  CHECK(session.current_step().address == 0x1010);
}

TEST_CASE("gdb stepper reports replay-log begin when reversing past start") {
  auto trace_path = write_block_trace("w1replay_gdb_stepper_reverse_begin.trace");

  auto inputs = build_session_inputs(trace_path);

  test_block_decoder decoder;
  w1::rewind::replay_session_config session_config{};
  session_config.stream = inputs.stream;
  session_config.index = inputs.index;
  session_config.context = inputs.context;
  session_config.thread_id = 1;
  session_config.track_registers = false;
  session_config.track_memory = false;
  session_config.block_decoder = &decoder;

  w1::rewind::replay_session session(session_config);
  REQUIRE(session.open());

  REQUIRE(session.step_instruction());
  CHECK(session.current_step().address == 0x1010);

  w1replay::gdb::run_policy policy{};
  policy.trace_is_block = true;
  policy.decoder_available = true;

  auto result = w1replay::gdb::resume_step(session, policy, {}, 1, gdbstub::resume_direction::reverse);

  CHECK(result.resume.state == gdbstub::resume_result::state::stopped);
  REQUIRE(result.resume.stop.replay_log.has_value());
  CHECK(*result.resume.stop.replay_log == gdbstub::replay_log_boundary::begin);
}

TEST_CASE("gdb stepper reverse-continues to breakpoint") {
  auto trace_path = write_block_trace("w1replay_gdb_stepper_reverse_break.trace");

  auto inputs = build_session_inputs(trace_path);

  test_block_decoder decoder;
  w1::rewind::replay_session_config session_config{};
  session_config.stream = inputs.stream;
  session_config.index = inputs.index;
  session_config.context = inputs.context;
  session_config.thread_id = 1;
  session_config.track_registers = false;
  session_config.track_memory = false;
  session_config.block_decoder = &decoder;

  w1::rewind::replay_session session(session_config);
  REQUIRE(session.open());

  REQUIRE(session.step_instruction());
  REQUIRE(session.step_instruction());
  CHECK(session.current_step().address == 0x1012);

  w1replay::gdb::run_policy policy{};
  policy.trace_is_block = true;
  policy.decoder_available = true;

  w1replay::gdb::breakpoint_store breakpoints;
  breakpoints.add(0x1010);
  auto result = w1replay::gdb::resume_continue(session, policy, breakpoints, 1, gdbstub::resume_direction::reverse);

  CHECK(result.resume.stop.kind == gdbstub::stop_kind::sw_break);
  CHECK(result.resume.stop.addr == 0x1010);
  CHECK(session.current_step().address == 0x1010);
}
