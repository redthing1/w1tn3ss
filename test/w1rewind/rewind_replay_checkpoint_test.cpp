#include <array>
#include <cstddef>
#include <filesystem>
#include <memory>
#include <string>

#include "doctest/doctest.hpp"

#include "w1rewind/replay/flow_cursor.hpp"
#include "w1rewind/replay/replay_context.hpp"
#include "w1rewind/replay/replay_session.hpp"
#include "w1rewind/replay/replay_state.hpp"
#include "w1rewind/replay/replay_state_applier.hpp"
#include "w1rewind/replay/stateful_flow_cursor.hpp"
#include "w1rewind/rewind_test_helpers.hpp"
#include "w1rewind/trace/replay_checkpoint.hpp"
#include "w1rewind/trace/trace_index.hpp"
#include "w1rewind/trace/trace_reader.hpp"

TEST_CASE("w1rewind replay checkpoint restores register state") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_checkpoint.trace");
  fs::path index_path = temp_path("w1rewind_replay_checkpoint.trace.w1ridx");
  fs::path checkpoint_path = temp_path("w1rewind_replay_checkpoint.trace.w1rchk");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header(0, 64);

  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1rewind.replay_checkpoint"));
  write_basic_metadata(handle.builder, "x86_64", arch, {"r0", "v0"});
  write_image_mapping(handle.builder, 1, 0x1000, 0x1000);

  w1::rewind::register_file_record regfile{};
  regfile.regfile_id = 0;
  regfile.name = "default";
  regfile.registers = {
      make_register_spec(0, "r0", static_cast<uint16_t>(arch.pointer_bits)),
      make_register_spec(1, "v0", 128),
  };
  REQUIRE(handle.builder.emit_register_file(regfile));

  write_thread_start(handle.builder, 1, "main");

  for (uint64_t seq = 0; seq < 4; ++seq) {
    write_instruction(handle.builder, 1, seq, 0x1000 + 0x10 + seq * 4);
    w1::rewind::reg_write_record reg_write{};
    reg_write.thread_id = 1;
    reg_write.sequence = seq;
    reg_write.regfile_id = 0;
    reg_write.entries.push_back(make_reg_write_entry(0, 0x1000 + seq));
    if (seq == 0) {
      reg_write.entries.push_back(w1::rewind::reg_write_entry{
          w1::rewind::reg_ref_kind::reg_id,
          0,
          0,
          16,
          1,
          "",
          {0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23, 0x30, 0x31, 0x32, 0x33, 0x40, 0x41, 0x42, 0x43},
      });
    }
    REQUIRE(handle.builder.emit_reg_write(reg_write));
  }

  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_index_options index_options;
  auto index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(w1::rewind::build_trace_index(
      trace_path.string(), index_path.string(), index_options, index.get(),
      redlog::get_logger("test.w1rewind.replay_checkpoint")
  ));

  w1::rewind::replay_context context;
  std::string context_error;
  REQUIRE(w1::rewind::load_replay_context(trace_path.string(), context, context_error));

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

  auto stream = std::make_shared<w1::rewind::trace_reader>(trace_path.string());
  w1::rewind::record_stream_cursor stream_cursor(stream);
  w1::rewind::flow_extractor extractor(&context);
  w1::rewind::history_window history(4);
  w1::rewind::flow_cursor cursor(std::move(stream_cursor), std::move(extractor), std::move(history), index);
  REQUIRE(cursor.open());

  w1::rewind::replay_state state;
  w1::rewind::replay_state_applier applier(context);
  w1::rewind::stateful_flow_cursor stateful_cursor(cursor, applier, state);
  REQUIRE(stateful_cursor.configure(context, true, false, nullptr));

  state.reset();
  state.set_register_files(context.register_files);
  {
    std::string apply_error;
    REQUIRE(state.apply_register_snapshot(checkpoint->regfile_id, checkpoint->registers, apply_error));
  }

  REQUIRE(cursor.seek_from_location(1, 2, checkpoint->location));

  w1::rewind::flow_step step{};
  REQUIRE(stateful_cursor.step_forward(step));
  CHECK(step.sequence == 2);

  const auto& state_view = stateful_cursor.state();
  CHECK(state_view.register_value(0, 0, w1::rewind::endian::little) == 0x1000 + 2);
  std::array<std::byte, 16> byte_out{};
  bool known = false;
  REQUIRE(state_view.copy_register_bytes(0, 1, byte_out, known));
  CHECK(known);
  CHECK(byte_out[0] == std::byte{0x10});
  CHECK(byte_out[15] == std::byte{0x43});

  auto session_stream = std::make_shared<w1::rewind::trace_reader>(trace_path.string());
  auto checkpoint_ptr = std::make_shared<w1::rewind::replay_checkpoint_index>(loaded);

  w1::rewind::replay_session_config session_config{};
  session_config.stream = session_stream;
  session_config.index = index;
  session_config.checkpoint = checkpoint_ptr;
  session_config.context = context;
  session_config.thread_id = 1;
  session_config.start_sequence = 2;
  session_config.track_registers = true;
  session_config.track_memory = false;

  w1::rewind::replay_session session(session_config);
  REQUIRE(session.open());
  REQUIRE(session.step_flow());
  CHECK(session.current_step().sequence == 2);
  auto regs = session.read_registers();
  REQUIRE(!regs.empty());
  CHECK(regs[0].has_value());
  CHECK(regs[0].value() == 0x1000 + 2);
  std::array<std::byte, 16> session_bytes{};
  bool session_known = false;
  REQUIRE(session.read_register_bytes(1, session_bytes, session_known));
  CHECK(session_known);
  CHECK(session_bytes[0] == std::byte{0x10});
  CHECK(session_bytes[15] == std::byte{0x43});

  cursor.close();
  session.close();

  fs::remove(trace_path);
  fs::remove(index_path);
  fs::remove(checkpoint_path);
}

TEST_CASE("w1rewind replay checkpoint restores mapping snapshot") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_checkpoint_mappings.trace");
  fs::path index_path = temp_path("w1rewind_replay_checkpoint_mappings.trace.w1ridx");
  fs::path checkpoint_path = temp_path("w1rewind_replay_checkpoint_mappings.trace.w1rchk");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header(0, 64);

  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1rewind.replay_checkpoint"));
  write_basic_metadata(handle.builder, "x86_64", arch, {"pc"});

  w1::rewind::image_record image1{};
  image1.image_id = 1;
  image1.name = "image1";
  REQUIRE(handle.builder.emit_image(image1));

  w1::rewind::image_record image2{};
  image2.image_id = 2;
  image2.name = "image2";
  REQUIRE(handle.builder.emit_image(image2));

  w1::rewind::mapping_record map1{};
  map1.kind = w1::rewind::mapping_event_kind::map;
  map1.space_id = 0;
  map1.base = 0x1000;
  map1.size = 0x100;
  map1.perms = w1::rewind::mapping_perm::read | w1::rewind::mapping_perm::exec;
  map1.image_id = 1;
  map1.name = "image1";
  REQUIRE(handle.builder.emit_mapping(map1));

  write_thread_start(handle.builder, 1, "main");
  write_instruction(handle.builder, 1, 0, 0x1000);

  w1::rewind::mapping_record unmap1{};
  unmap1.kind = w1::rewind::mapping_event_kind::unmap;
  unmap1.space_id = 0;
  unmap1.base = 0x1000;
  unmap1.size = 0x100;
  REQUIRE(handle.builder.emit_mapping(unmap1));

  w1::rewind::mapping_record map2{};
  map2.kind = w1::rewind::mapping_event_kind::map;
  map2.space_id = 0;
  map2.base = 0x2000;
  map2.size = 0x100;
  map2.perms = w1::rewind::mapping_perm::read | w1::rewind::mapping_perm::exec;
  map2.image_id = 2;
  map2.name = "image2";
  REQUIRE(handle.builder.emit_mapping(map2));

  write_instruction(handle.builder, 1, 1, 0x2000);
  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_index_options index_options;
  auto index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(w1::rewind::build_trace_index(
      trace_path.string(), index_path.string(), index_options, index.get(),
      redlog::get_logger("test.w1rewind.replay_checkpoint")
  ));

  w1::rewind::replay_context context;
  std::string context_error;
  REQUIRE(w1::rewind::load_replay_context(trace_path.string(), context, context_error));
  REQUIRE(context.features.has_mapping_events);

  w1::rewind::replay_checkpoint_config checkpoint_config{};
  checkpoint_config.trace_path = trace_path.string();
  checkpoint_config.output_path = checkpoint_path.string();
  checkpoint_config.stride = 1;

  w1::rewind::replay_checkpoint_index checkpoint_index;
  std::string error;
  REQUIRE(w1::rewind::build_replay_checkpoint(checkpoint_config, &checkpoint_index, error));

  w1::rewind::replay_checkpoint_index loaded;
  REQUIRE(w1::rewind::load_replay_checkpoint(checkpoint_path.string(), loaded, error));
  REQUIRE((loaded.header.flags & w1::rewind::k_checkpoint_flag_has_mappings) != 0);

  auto* checkpoint = loaded.find_checkpoint(1, 1);
  REQUIRE(checkpoint != nullptr);
  CHECK(checkpoint->sequence == 1);

  auto session_stream = std::make_shared<w1::rewind::trace_reader>(trace_path.string());
  auto checkpoint_ptr = std::make_shared<w1::rewind::replay_checkpoint_index>(loaded);

  w1::rewind::replay_session_config session_config{};
  session_config.stream = session_stream;
  session_config.index = index;
  session_config.checkpoint = checkpoint_ptr;
  session_config.context = context;
  session_config.thread_id = 1;
  session_config.start_sequence = 1;
  session_config.track_registers = true;
  session_config.track_memory = false;

  w1::rewind::replay_session session(session_config);
  REQUIRE(session.open());
  REQUIRE(session.step_flow());
  CHECK(session.current_step().sequence == 1);

  const auto* mappings = session.mappings();
  REQUIRE(mappings != nullptr);
  uint64_t offset = 0;
  CHECK(mappings->find_mapping_for_address(0, 0x1000, 1, offset) == nullptr);
  auto mapped = mappings->find_mapping_for_address(0, 0x2000, 1, offset);
  REQUIRE(mapped != nullptr);
  CHECK(mapped->image_id == 2);

  session.close();

  fs::remove(trace_path);
  fs::remove(index_path);
  fs::remove(checkpoint_path);
}
