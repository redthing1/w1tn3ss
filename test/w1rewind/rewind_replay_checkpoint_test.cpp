#include <filesystem>

#include "doctest/doctest.hpp"

#include "w1rewind/rewind_test_helpers.hpp"
#include "w1rewind/replay/replay_checkpoint.hpp"
#include "w1rewind/replay/replay_flow_cursor.hpp"
#include "w1rewind/replay/replay_session.hpp"
#include "w1rewind/replay/trace_index.hpp"
#include "w1rewind/record/trace_writer.hpp"

namespace {

std::vector<std::string> make_register_names(w1::rewind::trace_arch arch) {
  switch (arch) {
  case w1::rewind::trace_arch::x86_64:
    return {"rax", "rsp"};
  case w1::rewind::trace_arch::x86:
    return {"eax", "esp"};
  case w1::rewind::trace_arch::aarch64:
  case w1::rewind::trace_arch::arm:
    return {"x0", "sp"};
  default:
    break;
  }
  return {"r0", "sp"};
}

} // namespace

TEST_CASE("w1rewind replay checkpoint restores register state") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_checkpoint.trace");
  fs::path index_path = temp_path("w1rewind_replay_checkpoint.trace.idx");
  fs::path checkpoint_path = temp_path("w1rewind_replay_checkpoint.trace.w1rchk");

  w1::rewind::trace_writer_config config;
  config.path = trace_path.string();
  config.log = redlog::get_logger("test.w1rewind.replay_checkpoint");
  config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_writer(config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1::rewind::trace_header header{};
  header.architecture = w1::rewind::detect_trace_arch();
  header.pointer_size = w1::rewind::detect_pointer_size();
  header.flags = w1::rewind::trace_flag_instructions | w1::rewind::trace_flag_register_deltas;
  REQUIRE(writer->write_header(header));

  write_register_table(*writer, make_register_names(header.architecture));
  write_module_table(*writer, 1, 0x1000);

  write_thread_start(*writer, 1, "main");

  for (uint64_t seq = 0; seq < 4; ++seq) {
    write_instruction(*writer, 1, seq, 1, 0x10 + seq * 4);
    write_register_delta(*writer, 1, seq, 0, 0x1000 + seq);
  }

  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  w1::rewind::trace_index index;
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, &index, config.log));

  w1::rewind::replay_checkpoint_config checkpoint_config{};
  checkpoint_config.trace_path = trace_path.string();
  checkpoint_config.output_path = checkpoint_path.string();
  checkpoint_config.stride = 2;

  w1::rewind::replay_checkpoint_index checkpoint_index;
  std::string error;
  REQUIRE(w1::rewind::build_replay_checkpoint(checkpoint_config, &checkpoint_index, error));

  w1::rewind::replay_checkpoint_index loaded;
  REQUIRE(w1::rewind::load_replay_checkpoint(checkpoint_path.string(), loaded, error));

  auto* checkpoint = loaded.find_checkpoint(1, 2);
  REQUIRE(checkpoint != nullptr);
  CHECK(checkpoint->sequence == 2);

  w1::rewind::replay_flow_cursor_config replay_config{};
  replay_config.trace_path = trace_path.string();
  replay_config.index_path = index_path.string();
  replay_config.history_size = 4;
  replay_config.track_registers = true;
  replay_config.track_memory = false;

  w1::rewind::replay_flow_cursor cursor(replay_config);
  REQUIRE(cursor.open());
  REQUIRE(cursor.seek_with_checkpoint(*checkpoint, 2));

  w1::rewind::flow_step step{};
  REQUIRE(cursor.step_forward(step));
  CHECK(step.sequence == 2);

  const auto* state = cursor.state();
  REQUIRE(state != nullptr);
  CHECK(state->register_value(0) == 0x1000 + 2);

  w1::rewind::replay_session_config session_config{};
  session_config.trace_path = trace_path.string();
  session_config.index_path = index_path.string();
  session_config.thread_id = 1;
  session_config.start_sequence = 2;
  session_config.track_registers = true;
  session_config.track_memory = false;
  session_config.checkpoint_path = checkpoint_path.string();

  w1::rewind::replay_session session(session_config);
  REQUIRE(session.open());
  REQUIRE(session.step_flow());
  CHECK(session.current_step().sequence == 2);
  auto regs = session.read_registers();
  REQUIRE(!regs.empty());
  CHECK(regs[0].has_value());
  CHECK(regs[0].value() == 0x1000 + 2);

  fs::remove(trace_path);
  fs::remove(index_path);
  fs::remove(checkpoint_path);
}
