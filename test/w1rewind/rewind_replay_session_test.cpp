#include <chrono>
#include <filesystem>
#include <string>

#include "doctest/doctest.hpp"

#include "w1rewind/rewind_test_helpers.hpp"
#include "w1rewind/replay/replay_decode.hpp"
#include "w1rewind/replay/replay_session.hpp"
#include "w1rewind/replay/trace_index.hpp"
#include "w1rewind/record/trace_writer.hpp"

namespace {

class test_block_decoder final : public w1::rewind::replay_block_decoder {
public:
  bool decode_block(
      const w1::rewind::replay_context&,
      uint64_t address,
      uint32_t size,
      w1::rewind::replay_decoded_block& out,
      std::string&
  ) override {
    if (size == 0 || (size % 2) != 0) {
      return false;
    }

    out.address = address;
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

TEST_CASE("w1rewind replay session steps through decoded block instructions") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_session_block.trace");
  fs::path index_path = temp_path("w1rewind_replay_session_block.trace.idx");

  w1::rewind::trace_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1rewind.replay.session");
  writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1::rewind::trace_header header{};
  header.architecture = w1::rewind::detect_trace_arch();
  header.pointer_size = w1::rewind::detect_pointer_size();
  header.flags = w1::rewind::trace_flag_blocks;
  REQUIRE(writer->write_header(header));

  write_basic_metadata(*writer, header.architecture, header.pointer_size, minimal_registers(header.architecture));
  write_module_table(*writer, 7, 0x2000);

  write_thread_start(*writer, 1, "thread1");

  write_block_def(*writer, 1, 0x2000 + 0x20, 4);
  write_block_def(*writer, 2, 0x2000 + 0x40, 4);
  write_block_exec(*writer, 1, 0, 1);
  write_block_exec(*writer, 1, 1, 2);

  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  w1::rewind::trace_index index;
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, &index, writer_config.log));

  test_block_decoder decoder;
  w1::rewind::replay_session_config config{};
  config.trace_path = trace_path.string();
  config.index_path = index_path.string();
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
  fs::path index_path = temp_path("w1rewind_replay_session_fallback.trace.idx");

  w1::rewind::trace_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1rewind.replay.session");
  writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1::rewind::trace_header header{};
  header.architecture = w1::rewind::detect_trace_arch();
  header.pointer_size = w1::rewind::detect_pointer_size();
  header.flags = w1::rewind::trace_flag_blocks;
  REQUIRE(writer->write_header(header));

  write_basic_metadata(*writer, header.architecture, header.pointer_size, minimal_registers(header.architecture));
  write_module_table(*writer, 9, 0x3000);

  write_thread_start(*writer, 1, "thread1");

  write_block_def(*writer, 1, 0x3000 + 0x10, 4);
  write_block_exec(*writer, 1, 0, 1);

  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  w1::rewind::trace_index index;
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, &index, writer_config.log));

  w1::rewind::replay_session_config config{};
  config.trace_path = trace_path.string();
  config.index_path = index_path.string();
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

TEST_CASE("w1rewind replay session rebuilds stale index when trace changes") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_session_rebuild.trace");
  fs::path index_path = temp_path("w1rewind_replay_session_rebuild.trace.idx");

  w1::rewind::trace_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1rewind.replay.session");
  writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1::rewind::trace_header header{};
  header.architecture = w1::rewind::detect_trace_arch();
  header.pointer_size = w1::rewind::detect_pointer_size();
  header.flags = w1::rewind::trace_flag_blocks;
  REQUIRE(writer->write_header(header));

  write_basic_metadata(*writer, header.architecture, header.pointer_size, minimal_registers(header.architecture));
  write_module_table(*writer, 5, 0x1000);
  write_thread_start(*writer, 1, "thread1");
  write_block_def(*writer, 1, 0x1000 + 0x10, 4);
  write_block_exec(*writer, 1, 0, 1);
  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  w1::rewind::trace_index index;
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, &index, writer_config.log));

  w1::rewind::trace_writer_config new_writer_config = writer_config;
  new_writer_config.chunk_size = 128;
  auto new_writer = w1::rewind::make_trace_writer(new_writer_config);
  REQUIRE(new_writer);
  REQUIRE(new_writer->open());

  w1::rewind::trace_header new_header{};
  new_header.architecture = header.architecture;
  new_header.pointer_size = header.pointer_size;
  new_header.flags = w1::rewind::trace_flag_blocks;
  REQUIRE(new_writer->write_header(new_header));

  write_basic_metadata(*new_writer, new_header.architecture, new_header.pointer_size,
                       minimal_registers(new_header.architecture));
  write_module_table(*new_writer, 5, 0x1000);
  write_thread_start(*new_writer, 1, "thread1");
  write_block_def(*new_writer, 1, 0x1000 + 0x20, 4);
  write_block_exec(*new_writer, 1, 0, 1);
  write_thread_end(*new_writer, 1);

  new_writer->flush();
  new_writer->close();

  auto new_time = fs::file_time_type::clock::now() + std::chrono::seconds(2);
  std::error_code time_error;
  fs::last_write_time(trace_path, new_time, time_error);
  REQUIRE(!time_error);

  w1::rewind::replay_session_config config{};
  config.trace_path = trace_path.string();
  config.index_path = index_path.string();
  config.thread_id = 1;
  config.track_registers = false;
  config.track_memory = false;

  w1::rewind::replay_session session(config);
  REQUIRE(session.open());

  w1::rewind::trace_index rebuilt;
  REQUIRE(w1::rewind::load_trace_index(index_path.string(), rebuilt, writer_config.log));
  CHECK(rebuilt.header.chunk_size == new_writer_config.chunk_size);
}

TEST_CASE("w1rewind replay session rebuilds index on mismatch even if trace is older") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_session_rebuild_mismatch.trace");
  fs::path index_path = temp_path("w1rewind_replay_session_rebuild_mismatch.trace.idx");

  w1::rewind::trace_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1rewind.replay.session");
  writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1::rewind::trace_header header{};
  header.architecture = w1::rewind::detect_trace_arch();
  header.pointer_size = w1::rewind::detect_pointer_size();
  header.flags = w1::rewind::trace_flag_blocks;
  REQUIRE(writer->write_header(header));

  write_basic_metadata(*writer, header.architecture, header.pointer_size, minimal_registers(header.architecture));
  write_module_table(*writer, 6, 0x1000);
  write_thread_start(*writer, 1, "thread1");
  write_block_def(*writer, 1, 0x1000 + 0x10, 4);
  write_block_exec(*writer, 1, 0, 1);
  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  w1::rewind::trace_index index;
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, &index, writer_config.log));

  auto index_time = fs::last_write_time(index_path);

  w1::rewind::trace_writer_config new_writer_config = writer_config;
  new_writer_config.chunk_size = 128;
  auto new_writer = w1::rewind::make_trace_writer(new_writer_config);
  REQUIRE(new_writer);
  REQUIRE(new_writer->open());

  w1::rewind::trace_header new_header{};
  new_header.architecture = header.architecture;
  new_header.pointer_size = header.pointer_size;
  new_header.flags = w1::rewind::trace_flag_blocks;
  REQUIRE(new_writer->write_header(new_header));

  write_basic_metadata(*new_writer, new_header.architecture, new_header.pointer_size,
                       minimal_registers(new_header.architecture));
  write_module_table(*new_writer, 6, 0x1000);
  write_thread_start(*new_writer, 1, "thread1");
  write_block_def(*new_writer, 1, 0x1000 + 0x20, 4);
  write_block_exec(*new_writer, 1, 0, 1);
  write_thread_end(*new_writer, 1);

  new_writer->flush();
  new_writer->close();

  std::error_code time_error;
  fs::last_write_time(trace_path, index_time - std::chrono::seconds(2), time_error);
  REQUIRE(!time_error);

  w1::rewind::replay_session_config config{};
  config.trace_path = trace_path.string();
  config.index_path = index_path.string();
  config.thread_id = 1;
  config.track_registers = false;
  config.track_memory = false;

  w1::rewind::replay_session session(config);
  REQUIRE(session.open());

  w1::rewind::trace_index rebuilt;
  REQUIRE(w1::rewind::load_trace_index(index_path.string(), rebuilt, writer_config.log));
  CHECK(rebuilt.header.chunk_size == new_writer_config.chunk_size);
}

TEST_CASE("w1rewind replay session supports reverse instruction stepping on block traces") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_session_reverse.trace");
  fs::path index_path = temp_path("w1rewind_replay_session_reverse.trace.idx");

  w1::rewind::trace_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1rewind.replay.session");
  writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1::rewind::trace_header header{};
  header.architecture = w1::rewind::detect_trace_arch();
  header.pointer_size = w1::rewind::detect_pointer_size();
  header.flags = w1::rewind::trace_flag_blocks;
  REQUIRE(writer->write_header(header));

  write_basic_metadata(*writer, header.architecture, header.pointer_size, minimal_registers(header.architecture));
  write_module_table(*writer, 11, 0x5000);

  write_thread_start(*writer, 1, "thread1");

  write_block_def(*writer, 1, 0x5000 + 0x20, 4);
  write_block_exec(*writer, 1, 0, 1);

  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  w1::rewind::trace_index index;
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, &index, writer_config.log));

  test_block_decoder decoder;
  w1::rewind::replay_session_config config{};
  config.trace_path = trace_path.string();
  config.index_path = index_path.string();
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
  fs::path index_path = temp_path("w1rewind_replay_session_state.trace.idx");

  w1::rewind::trace_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1rewind.replay.session");
  writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1::rewind::trace_header header{};
  header.architecture = w1::rewind::detect_trace_arch();
  header.pointer_size = w1::rewind::detect_pointer_size();
  header.flags = w1::rewind::trace_flag_blocks | w1::rewind::trace_flag_register_deltas;
  REQUIRE(writer->write_header(header));

  write_basic_metadata(*writer, header.architecture, header.pointer_size, {"r0"});
  write_module_table(*writer, 12, 0x6000);

  write_thread_start(*writer, 1, "thread1");

  write_block_def(*writer, 1, 0x6000 + 0x20, 4);
  write_block_def(*writer, 2, 0x6000 + 0x40, 4);
  write_block_exec(*writer, 1, 0, 1);
  write_register_delta(*writer, 1, 0, 0, 0x1000);
  write_block_exec(*writer, 1, 1, 2);
  write_register_delta(*writer, 1, 1, 0, 0x1001);

  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  w1::rewind::trace_index index;
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, &index, writer_config.log));

  test_block_decoder decoder;
  w1::rewind::replay_session_config config{};
  config.trace_path = trace_path.string();
  config.index_path = index_path.string();
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
  fs::path index_path = temp_path("w1rewind_replay_session_reverse_inst.trace.idx");

  w1::rewind::trace_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1rewind.replay.session");
  writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1::rewind::trace_header header{};
  header.architecture = w1::rewind::detect_trace_arch();
  header.pointer_size = w1::rewind::detect_pointer_size();
  header.flags = w1::rewind::trace_flag_instructions | w1::rewind::trace_flag_register_deltas;
  REQUIRE(writer->write_header(header));

  write_basic_metadata(*writer, header.architecture, header.pointer_size, {"r0"});
  write_module_table(*writer, 13, 0x7000);

  write_thread_start(*writer, 1, "thread1");

  for (uint64_t seq = 0; seq < 3; ++seq) {
    write_instruction(*writer, 1, seq, 0x7000 + 0x10 + seq * 4);
    write_register_delta(*writer, 1, seq, 0, 0x2000 + seq);
  }

  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  w1::rewind::trace_index index;
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, &index, writer_config.log));

  w1::rewind::replay_session_config config{};
  config.trace_path = trace_path.string();
  config.index_path = index_path.string();
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
