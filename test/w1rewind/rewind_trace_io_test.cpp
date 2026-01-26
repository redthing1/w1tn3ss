#include <filesystem>

#include "doctest/doctest.hpp"

#include "w1rewind/replay/replay_context.hpp"
#include "w1rewind/rewind_test_helpers.hpp"
#include "w1rewind/trace/trace_reader.hpp"

namespace {

std::filesystem::path make_temp_path(const char* name) { return std::filesystem::temp_directory_path() / name; }

} // namespace

TEST_CASE("rewind trace writer and reader round trip (instructions)") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path path = make_temp_path("w1rewind_trace_io_instruction.trace");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header();

  auto handle = open_trace(path, header);
  write_basic_metadata(handle.builder, "x86_64", arch, {"r0", "r1"});
  write_image_mapping(handle.builder, 1, 0x1000, 0x2000, "/bin/test_module");

  write_thread_start(handle.builder, 1, "main");
  write_instruction(handle.builder, 1, 1, 0x1010, 4);

  w1::rewind::reg_write_record reg_write{};
  reg_write.thread_id = 1;
  reg_write.sequence = 1;
  reg_write.regfile_id = 0;
  reg_write.entries = {
      make_reg_write_entry(0, 0x1111),
      make_reg_write_entry(1, 0x2222),
  };
  REQUIRE(handle.builder.emit_reg_write(reg_write));

  write_memory_access(handle.builder, 1, 1, w1::rewind::mem_access_op::write, 0x2000, {0x01, 0x02, 0x03, 0x04});

  w1::rewind::memory_segment segment{};
  segment.space_id = 0;
  segment.base = 0x3000;
  segment.bytes = {0x10, 0x20};
  write_snapshot(handle.builder, 1, 1, {make_reg_write_entry(0, 0xAAAA), make_reg_write_entry(1, 0xBBBB)}, {segment});

  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_reader reader(path.string());
  REQUIRE(reader.open());
  CHECK(reader.header().version == w1::rewind::k_trace_version);
  CHECK(reader.header().default_chunk_size > 0);

  std::vector<w1::rewind::trace_record> records;
  w1::rewind::trace_record record;
  while (reader.read_next(record)) {
    records.push_back(record);
  }
  CHECK(reader.error().empty());
  REQUIRE(records.size() == 12);

  CHECK(std::holds_alternative<w1::rewind::arch_descriptor_record>(records[0]));
  CHECK(std::holds_alternative<w1::rewind::environment_record>(records[1]));
  CHECK(std::holds_alternative<w1::rewind::address_space_record>(records[2]));
  CHECK(std::holds_alternative<w1::rewind::register_file_record>(records[3]));
  CHECK(std::holds_alternative<w1::rewind::image_record>(records[4]));
  CHECK(std::holds_alternative<w1::rewind::mapping_record>(records[5]));
  CHECK(std::holds_alternative<w1::rewind::thread_start_record>(records[6]));
  CHECK(std::holds_alternative<w1::rewind::flow_instruction_record>(records[7]));
  CHECK(std::holds_alternative<w1::rewind::reg_write_record>(records[8]));
  CHECK(std::holds_alternative<w1::rewind::mem_access_record>(records[9]));
  CHECK(std::holds_alternative<w1::rewind::snapshot_record>(records[10]));
  CHECK(std::holds_alternative<w1::rewind::thread_end_record>(records[11]));

  const auto& reg_record = std::get<w1::rewind::reg_write_record>(records[8]);
  REQUIRE(reg_record.entries.size() == 2);
  CHECK(reg_record.entries[0].reg_id == 0);
  CHECK(reg_record.entries[1].reg_id == 1);

  const auto& image_record = std::get<w1::rewind::image_record>(records[4]);
  CHECK(image_record.path == "/bin/test_module");
  CHECK(image_record.flags == 0);

  w1::rewind::replay_context context;
  std::string error;
  REQUIRE(w1::rewind::load_replay_context(path.string(), context, error));
  CHECK(context.arch.has_value());
  CHECK(context.environment.has_value());
  CHECK(context.features.has_flow_instruction);
  CHECK(context.features.has_reg_writes);
  CHECK(context.features.has_mem_access);
  CHECK(context.features.has_snapshots);

  reader.close();
  fs::remove(path);
}

TEST_CASE("replay context rejects overlapping image blobs") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path path = make_temp_path("w1rewind_trace_io_blob_overlap.trace");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header();

  auto handle = open_trace(path, header);
  write_basic_metadata(handle.builder, "x86_64", arch, {"pc"});
  write_image_mapping(handle.builder, 1, 0x1000, 0x100, "blob_image");

  w1::rewind::image_blob_record blob1{};
  blob1.image_id = 1;
  blob1.offset = 0;
  blob1.data = {0x01, 0x02, 0x03, 0x04};
  REQUIRE(handle.builder.emit_image_blob(blob1));

  w1::rewind::image_blob_record blob2{};
  blob2.image_id = 1;
  blob2.offset = 2;
  blob2.data = {0xAA, 0xBB, 0xCC, 0xDD};
  REQUIRE(handle.builder.emit_image_blob(blob2));

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::replay_context context;
  std::string error;
  CHECK_FALSE(w1::rewind::load_replay_context(path.string(), context, error));
  CHECK(error == "image blob ranges overlap");

  fs::remove(path);
}

TEST_CASE("replay context accepts empty image blob records") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path path = make_temp_path("w1rewind_trace_io_blob_empty.trace");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header();

  auto handle = open_trace(path, header);
  write_basic_metadata(handle.builder, "x86_64", arch, {"pc"});
  write_image_mapping(handle.builder, 1, 0x1000, 0x100, "empty_blob_image");

  w1::rewind::image_blob_record blob{};
  blob.image_id = 1;
  blob.offset = 0;
  blob.data.clear();
  REQUIRE(handle.builder.emit_image_blob(blob));

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::replay_context context;
  std::string error;
  REQUIRE(w1::rewind::load_replay_context(path.string(), context, error));
  CHECK(context.features.has_image_blobs);
  REQUIRE(context.image_blobs_by_id.count(1) == 1);
  REQUIRE(context.image_blobs_by_id[1].size() == 1);
  CHECK(context.image_blobs_by_id[1][0].data.empty());

  fs::remove(path);
}

TEST_CASE("rewind trace writer and reader round trip (image blobs)") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path path = make_temp_path("w1rewind_trace_io_blob.trace");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header();

  auto handle = open_trace(path, header);
  write_basic_metadata(handle.builder, "x86_64", arch, {"pc"});
  write_image_mapping(handle.builder, 1, 0x1000, 0x100, "blob_image");

  std::vector<uint8_t> blob_bytes = {0xAA, 0xBB, 0xCC};
  REQUIRE(handle.builder.emit_image_blob_range(1, 4, blob_bytes));

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_reader reader(path.string());
  REQUIRE(reader.open());

  bool found_blob = false;
  w1::rewind::trace_record record;
  while (reader.read_next(record)) {
    if (std::holds_alternative<w1::rewind::image_blob_record>(record)) {
      const auto& blob = std::get<w1::rewind::image_blob_record>(record);
      CHECK(blob.image_id == 1);
      CHECK(blob.offset == 4);
      REQUIRE(blob.data.size() == blob_bytes.size());
      CHECK(blob.data[0] == blob_bytes[0]);
      CHECK(blob.data[1] == blob_bytes[1]);
      CHECK(blob.data[2] == blob_bytes[2]);
      found_blob = true;
      break;
    }
  }
  CHECK(found_blob);

  w1::rewind::replay_context context;
  std::string error;
  REQUIRE(w1::rewind::load_replay_context(path.string(), context, error));
  CHECK(context.features.has_image_blobs);
  REQUIRE(context.image_blobs_by_id.count(1) == 1);
  REQUIRE(context.image_blobs_by_id[1].size() == 1);
  CHECK(context.image_blobs_by_id[1][0].offset == 4);

  reader.close();
  fs::remove(path);
}

TEST_CASE("rewind trace writer and reader round trip (image metadata)") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path path = make_temp_path("w1rewind_trace_io_metadata.trace");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header();

  auto handle = open_trace(path, header);
  write_basic_metadata(handle.builder, "x86_64", arch, {"pc"});
  write_image_mapping(handle.builder, 1, 0x1000, 0x100, "meta_image");

  w1::rewind::image_metadata_record meta{};
  meta.image_id = 1;
  meta.format = "macho";
  meta.flags =
      w1::rewind::image_meta_has_uuid | w1::rewind::image_meta_has_macho_header | w1::rewind::image_meta_has_segments;
  meta.uuid = "TEST-UUID";
  meta.macho_header.magic = 1;
  meta.macho_header.cputype = 2;
  meta.macho_header.cpusubtype = 3;
  meta.macho_header.filetype = 4;
  meta.segments.push_back({"__TEXT", 0x1000, 0x2000, 0, 0x2000, 7});

  REQUIRE(handle.builder.emit_image_metadata(meta));

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_reader reader(path.string());
  REQUIRE(reader.open());

  bool found_meta = false;
  w1::rewind::trace_record record;
  while (reader.read_next(record)) {
    if (std::holds_alternative<w1::rewind::image_metadata_record>(record)) {
      const auto& decoded = std::get<w1::rewind::image_metadata_record>(record);
      CHECK(decoded.image_id == 1);
      CHECK(decoded.format == "macho");
      CHECK(decoded.uuid == "TEST-UUID");
      CHECK((decoded.flags & w1::rewind::image_meta_has_macho_header) != 0);
      REQUIRE(decoded.segments.size() == 1);
      CHECK(decoded.segments[0].name == "__TEXT");
      found_meta = true;
      break;
    }
  }
  CHECK(found_meta);

  w1::rewind::replay_context context;
  std::string error;
  REQUIRE(w1::rewind::load_replay_context(path.string(), context, error));
  CHECK(context.features.has_image_metadata);
  REQUIRE(context.image_metadata_by_id.count(1) == 1);
  CHECK(context.image_metadata_by_id.at(1).uuid == "TEST-UUID");

  reader.close();
  fs::remove(path);
}

#if defined(WITNESS_REWIND_HAVE_ZSTD)
TEST_CASE("rewind trace writer and reader round trip (compressed blocks)") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path path = make_temp_path("w1rewind_trace_io_compressed_block.trace");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header();

  w1::rewind::trace_file_writer_config config;
  config.path = path.string();
  config.log = redlog::get_logger("test.w1rewind.trace");
  config.codec = w1::rewind::compression::zstd;

  auto writer = w1::rewind::make_trace_file_writer(config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1::rewind::trace_builder_config builder_config;
  builder_config.sink = writer;
  builder_config.log = config.log;
  w1::rewind::trace_builder builder(builder_config);
  REQUIRE(builder.begin_trace(header));

  write_basic_metadata(builder, "x86_64", arch, {"r0"});
  write_image_mapping(builder, 1, 0x1000, 0x2000, "/bin/test_module");

  write_thread_start(builder, 1, "main");
  write_block_def(builder, 10, 0x1080, 12);
  write_block_exec(builder, 1, 1, 10);
  write_thread_end(builder, 1);

  builder.flush();
  writer->close();

  w1::rewind::trace_reader reader(path.string());
  REQUIRE(reader.open());
  CHECK(reader.header().version == w1::rewind::k_trace_version);

  std::vector<w1::rewind::trace_record> records;
  w1::rewind::trace_record record;
  while (reader.read_next(record)) {
    records.push_back(record);
  }
  CHECK(reader.error().empty());
  REQUIRE(records.size() == 10);

  CHECK(std::holds_alternative<w1::rewind::arch_descriptor_record>(records[0]));
  CHECK(std::holds_alternative<w1::rewind::environment_record>(records[1]));
  CHECK(std::holds_alternative<w1::rewind::address_space_record>(records[2]));
  CHECK(std::holds_alternative<w1::rewind::register_file_record>(records[3]));
  CHECK(std::holds_alternative<w1::rewind::image_record>(records[4]));
  CHECK(std::holds_alternative<w1::rewind::mapping_record>(records[5]));
  CHECK(std::holds_alternative<w1::rewind::thread_start_record>(records[6]));
  CHECK(std::holds_alternative<w1::rewind::block_definition_record>(records[7]));
  CHECK(std::holds_alternative<w1::rewind::block_exec_record>(records[8]));
  CHECK(std::holds_alternative<w1::rewind::thread_end_record>(records[9]));

  reader.close();
  fs::remove(path);
}
#endif

TEST_CASE("rewind trace writer and reader round trip (reg write bytes)") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path path = make_temp_path("w1rewind_trace_io_regbytes.trace");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header();

  auto handle = open_trace(path, header);
  write_basic_metadata(handle.builder, "x86_64", arch, {"r0", "v0"});

  w1::rewind::reg_write_record reg_write{};
  reg_write.thread_id = 1;
  reg_write.sequence = 0;
  reg_write.regfile_id = 0;
  reg_write.entries = {
      w1::rewind::reg_write_entry{
          w1::rewind::reg_ref_kind::reg_id,
          0,
          0,
          16,
          1,
          "",
          {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
      },
  };
  REQUIRE(handle.builder.emit_reg_write(reg_write));

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_reader reader(path.string());
  REQUIRE(reader.open());

  bool saw_bytes = false;
  w1::rewind::trace_record record;
  while (reader.read_next(record)) {
    if (std::holds_alternative<w1::rewind::reg_write_record>(record)) {
      const auto& decoded = std::get<w1::rewind::reg_write_record>(record);
      REQUIRE(decoded.entries.size() == 1);
      CHECK(decoded.entries[0].reg_id == 1);
      CHECK(decoded.entries[0].value.size() == 16);
      CHECK(decoded.entries[0].value[0] == 0x00);
      CHECK(decoded.entries[0].value[15] == 0x0f);
      saw_bytes = true;
    }
  }
  CHECK(reader.error().empty());
  CHECK(saw_bytes);

  reader.close();
  fs::remove(path);
}

TEST_CASE("rewind trace writer and reader round trip (reg write names)") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path path = make_temp_path("w1rewind_trace_io_regname.trace");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header();

  auto handle = open_trace(path, header);
  write_basic_metadata(handle.builder, "x86_64", arch, {"pc", "sp"});

  w1::rewind::reg_write_record reg_write{};
  reg_write.thread_id = 1;
  reg_write.sequence = 0;
  reg_write.regfile_id = 0;
  w1::rewind::reg_write_entry entry{};
  entry.ref_kind = w1::rewind::reg_ref_kind::reg_name;
  entry.byte_offset = 0;
  entry.byte_size = 8;
  entry.reg_name = "pc";
  entry.value = encode_value(0x1122334455667788ULL, entry.byte_size, w1::rewind::endian::little);
  reg_write.entries = {entry};
  REQUIRE(handle.builder.emit_reg_write(reg_write));

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_reader reader(path.string());
  REQUIRE(reader.open());

  bool saw_entry = false;
  w1::rewind::trace_record record;
  while (reader.read_next(record)) {
    if (std::holds_alternative<w1::rewind::reg_write_record>(record)) {
      const auto& decoded = std::get<w1::rewind::reg_write_record>(record);
      REQUIRE(decoded.entries.size() == 1);
      CHECK(decoded.entries[0].ref_kind == w1::rewind::reg_ref_kind::reg_name);
      CHECK(decoded.entries[0].reg_name == "pc");
      CHECK(decoded.entries[0].value.size() == 8);
      CHECK(decoded.entries[0].value[0] == 0x88);
      CHECK(decoded.entries[0].value[7] == 0x11);
      saw_entry = true;
    }
  }
  CHECK(reader.error().empty());
  CHECK(saw_entry);

  reader.close();
  fs::remove(path);
}
