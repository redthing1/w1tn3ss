#include <filesystem>

#include "doctest/doctest.hpp"

#include "w1rewind/replay/trace_reader.hpp"
#include "w1rewind/record/trace_writer.hpp"

namespace {

std::filesystem::path make_temp_path(const char* name) {
  return std::filesystem::temp_directory_path() / name;
}

} // namespace

TEST_CASE("rewind trace writer and reader round trip (instructions)") {
  namespace fs = std::filesystem;

  fs::path path = make_temp_path("w1rewind_trace_io_instruction.trace");

  w1::rewind::trace_writer_config config;
  config.path = path.string();
  config.log = redlog::get_logger("test.w1rewind.trace");

  auto writer = w1::rewind::make_trace_writer(config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1::rewind::trace_header header{};
  header.architecture = w1::rewind::detect_trace_arch();
  header.pointer_size = w1::rewind::detect_pointer_size();
  header.flags = w1::rewind::trace_flag_instructions | w1::rewind::trace_flag_register_deltas |
                 w1::rewind::trace_flag_memory_access | w1::rewind::trace_flag_memory_values |
                 w1::rewind::trace_flag_snapshots | w1::rewind::trace_flag_stack_snapshot;
  REQUIRE(writer->write_header(header));

  w1::rewind::register_table_record reg_table{};
  reg_table.names = {"r0", "r1"};
  REQUIRE(writer->write_register_table(reg_table));

  w1::rewind::module_record module{};
  module.id = 1;
  module.base = 0x1000;
  module.size = 0x2000;
  module.permissions = w1::rewind::module_perm::read | w1::rewind::module_perm::exec;
  module.path = "/bin/test_module";

  w1::rewind::module_table_record mod_table{};
  mod_table.modules = {module};
  REQUIRE(writer->write_module_table(mod_table));

  w1::rewind::thread_start_record start{};
  start.thread_id = 1;
  start.name = "main";
  REQUIRE(writer->write_thread_start(start));

  w1::rewind::instruction_record instruction{};
  instruction.sequence = 1;
  instruction.thread_id = 1;
  instruction.module_id = 1;
  instruction.module_offset = 0x10;
  instruction.size = 4;
  REQUIRE(writer->write_instruction(instruction));

  w1::rewind::register_delta_record deltas{};
  deltas.sequence = 1;
  deltas.thread_id = 1;
  deltas.deltas = {
      w1::rewind::register_delta{0, 0x1111},
      w1::rewind::register_delta{1, 0x2222},
  };
  REQUIRE(writer->write_register_deltas(deltas));

  w1::rewind::memory_access_record mem{};
  mem.sequence = 1;
  mem.thread_id = 1;
  mem.kind = w1::rewind::memory_access_kind::write;
  mem.address = 0x2000;
  mem.size = 4;
  mem.value_known = true;
  mem.data = {0x01, 0x02, 0x03, 0x04};
  REQUIRE(writer->write_memory_access(mem));

  w1::rewind::snapshot_record snapshot{};
  snapshot.snapshot_id = 7;
  snapshot.sequence = 1;
  snapshot.thread_id = 1;
  snapshot.registers = {
      w1::rewind::register_delta{0, 0xAAAA},
      w1::rewind::register_delta{1, 0xBBBB},
  };
  snapshot.stack_snapshot = {0x10, 0x20};
  snapshot.reason = "interval";
  REQUIRE(writer->write_snapshot(snapshot));

  w1::rewind::thread_end_record end{};
  end.thread_id = 1;
  REQUIRE(writer->write_thread_end(end));

  writer->flush();
  writer->close();

  w1::rewind::trace_reader reader(path.string());
  REQUIRE(reader.open());
  CHECK(reader.header().version == w1::rewind::k_trace_version);
  CHECK(reader.header().architecture == w1::rewind::detect_trace_arch());
  CHECK(reader.header().pointer_size == w1::rewind::detect_pointer_size());
  CHECK(reader.header().compression == w1::rewind::trace_compression::none);
  CHECK(reader.header().chunk_size == w1::rewind::k_trace_chunk_bytes);
  CHECK((reader.header().flags & w1::rewind::trace_flag_instructions) != 0);
  CHECK((reader.header().flags & w1::rewind::trace_flag_blocks) == 0);

  std::vector<w1::rewind::trace_record> records;
  w1::rewind::trace_record record;
  while (reader.read_next(record)) {
    records.push_back(record);
  }
  CHECK(reader.error().empty());
  REQUIRE(records.size() == 8);

  CHECK(std::holds_alternative<w1::rewind::register_table_record>(records[0]));
  CHECK(std::holds_alternative<w1::rewind::module_table_record>(records[1]));
  CHECK(std::holds_alternative<w1::rewind::thread_start_record>(records[2]));
  CHECK(std::holds_alternative<w1::rewind::instruction_record>(records[3]));
  CHECK(std::holds_alternative<w1::rewind::register_delta_record>(records[4]));
  CHECK(std::holds_alternative<w1::rewind::memory_access_record>(records[5]));
  CHECK(std::holds_alternative<w1::rewind::snapshot_record>(records[6]));
  CHECK(std::holds_alternative<w1::rewind::thread_end_record>(records[7]));

  fs::remove(path);
}

#if defined(W1_REWIND_HAVE_ZSTD)
TEST_CASE("rewind trace writer and reader round trip (compressed blocks)") {
  namespace fs = std::filesystem;

  fs::path path = make_temp_path("w1rewind_trace_io_compressed_block.trace");

  w1::rewind::trace_writer_config config;
  config.path = path.string();
  config.log = redlog::get_logger("test.w1rewind.trace");
  config.compression = w1::rewind::trace_compression::zstd;

  auto writer = w1::rewind::make_trace_writer(config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1::rewind::trace_header header{};
  header.architecture = w1::rewind::detect_trace_arch();
  header.pointer_size = w1::rewind::detect_pointer_size();
  header.flags = w1::rewind::trace_flag_blocks;
  REQUIRE(writer->write_header(header));

  w1::rewind::register_table_record reg_table{};
  reg_table.names = {"r0"};
  REQUIRE(writer->write_register_table(reg_table));

  w1::rewind::module_record module{};
  module.id = 1;
  module.base = 0x1000;
  module.size = 0x2000;
  module.permissions = w1::rewind::module_perm::read | w1::rewind::module_perm::exec;
  module.path = "/bin/test_module";

  w1::rewind::module_table_record mod_table{};
  mod_table.modules = {module};
  REQUIRE(writer->write_module_table(mod_table));

  w1::rewind::thread_start_record start{};
  start.thread_id = 1;
  start.name = "main";
  REQUIRE(writer->write_thread_start(start));

  w1::rewind::block_definition_record block_def{};
  block_def.block_id = 10;
  block_def.module_id = 1;
  block_def.module_offset = 0x80;
  block_def.size = 12;
  REQUIRE(writer->write_block_definition(block_def));

  w1::rewind::block_exec_record block_exec{};
  block_exec.sequence = 1;
  block_exec.thread_id = 1;
  block_exec.block_id = 10;
  REQUIRE(writer->write_block_exec(block_exec));

  w1::rewind::thread_end_record end{};
  end.thread_id = 1;
  REQUIRE(writer->write_thread_end(end));

  writer->flush();
  writer->close();

  w1::rewind::trace_reader reader(path.string());
  REQUIRE(reader.open());
  CHECK(reader.header().version == w1::rewind::k_trace_version);
  CHECK(reader.header().compression == w1::rewind::trace_compression::zstd);
  CHECK((reader.header().flags & w1::rewind::trace_flag_blocks) != 0);

  std::vector<w1::rewind::trace_record> records;
  w1::rewind::trace_record record;
  while (reader.read_next(record)) {
    records.push_back(record);
  }
  CHECK(reader.error().empty());
  REQUIRE(records.size() == 6);

  CHECK(std::holds_alternative<w1::rewind::register_table_record>(records[0]));
  CHECK(std::holds_alternative<w1::rewind::module_table_record>(records[1]));
  CHECK(std::holds_alternative<w1::rewind::thread_start_record>(records[2]));
  CHECK(std::holds_alternative<w1::rewind::block_definition_record>(records[3]));
  CHECK(std::holds_alternative<w1::rewind::block_exec_record>(records[4]));
  CHECK(std::holds_alternative<w1::rewind::thread_end_record>(records[5]));

  fs::remove(path);
}
#endif

TEST_CASE("rewind trace writer and reader round trip (blocks)") {
  namespace fs = std::filesystem;

  fs::path path = make_temp_path("w1rewind_trace_io_block.trace");

  w1::rewind::trace_writer_config config;
  config.path = path.string();
  config.log = redlog::get_logger("test.w1rewind.trace");

  auto writer = w1::rewind::make_trace_writer(config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1::rewind::trace_header header{};
  header.architecture = w1::rewind::detect_trace_arch();
  header.pointer_size = w1::rewind::detect_pointer_size();
  header.flags = w1::rewind::trace_flag_blocks | w1::rewind::trace_flag_snapshots;
  REQUIRE(writer->write_header(header));

  w1::rewind::register_table_record reg_table{};
  reg_table.names = {"r0", "r1"};
  REQUIRE(writer->write_register_table(reg_table));

  w1::rewind::module_record module{};
  module.id = 1;
  module.base = 0x5000;
  module.size = 0x2000;
  module.permissions = w1::rewind::module_perm::read | w1::rewind::module_perm::exec;
  module.path = "/bin/test_module";

  w1::rewind::module_table_record mod_table{};
  mod_table.modules = {module};
  REQUIRE(writer->write_module_table(mod_table));

  w1::rewind::thread_start_record start{};
  start.thread_id = 1;
  start.name = "main";
  REQUIRE(writer->write_thread_start(start));

  w1::rewind::block_definition_record block_def{};
  block_def.block_id = 10;
  block_def.module_id = 1;
  block_def.module_offset = 0x100;
  block_def.size = 12;
  REQUIRE(writer->write_block_definition(block_def));

  w1::rewind::block_exec_record block_exec{};
  block_exec.sequence = 1;
  block_exec.thread_id = 1;
  block_exec.block_id = 10;
  REQUIRE(writer->write_block_exec(block_exec));

  w1::rewind::snapshot_record snapshot{};
  snapshot.snapshot_id = 3;
  snapshot.sequence = 1;
  snapshot.thread_id = 1;
  snapshot.registers = {
      w1::rewind::register_delta{0, 0xAAAA},
      w1::rewind::register_delta{1, 0xBBBB},
  };
  snapshot.stack_snapshot = {};
  snapshot.reason = "interval";
  REQUIRE(writer->write_snapshot(snapshot));

  w1::rewind::thread_end_record end{};
  end.thread_id = 1;
  REQUIRE(writer->write_thread_end(end));

  writer->flush();
  writer->close();

  w1::rewind::trace_reader reader(path.string());
  REQUIRE(reader.open());
  CHECK(reader.header().version == w1::rewind::k_trace_version);
  CHECK(reader.header().compression == w1::rewind::trace_compression::none);
  CHECK(reader.header().chunk_size == w1::rewind::k_trace_chunk_bytes);
  CHECK((reader.header().flags & w1::rewind::trace_flag_blocks) != 0);
  CHECK((reader.header().flags & w1::rewind::trace_flag_instructions) == 0);

  std::vector<w1::rewind::trace_record> records;
  w1::rewind::trace_record record;
  while (reader.read_next(record)) {
    records.push_back(record);
  }
  CHECK(reader.error().empty());
  REQUIRE(records.size() == 7);

  CHECK(std::holds_alternative<w1::rewind::register_table_record>(records[0]));
  CHECK(std::holds_alternative<w1::rewind::module_table_record>(records[1]));
  CHECK(std::holds_alternative<w1::rewind::thread_start_record>(records[2]));
  CHECK(std::holds_alternative<w1::rewind::block_definition_record>(records[3]));
  CHECK(std::holds_alternative<w1::rewind::block_exec_record>(records[4]));
  CHECK(std::holds_alternative<w1::rewind::snapshot_record>(records[5]));
  CHECK(std::holds_alternative<w1::rewind::thread_end_record>(records[6]));
  CHECK(reader.block_table().size() == 1);

  fs::remove(path);
}
