#include <filesystem>

#include "doctest/doctest.hpp"

#include "w1rewind/replay/replay_context.hpp"
#include "w1rewind/rewind_test_helpers.hpp"

TEST_CASE("replay context finds mapping for addresses") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_mapping_lookup.trace");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header();
  auto handle = open_trace(trace_path, header);
  write_basic_metadata(handle.builder, "x86_64", arch, {"pc"});

  write_image_mapping(handle.builder, 1, 0x1000, 0x100, "mod1");
  write_image_mapping(handle.builder, 2, 0x2000, 0x80, "mod2");

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::replay_context context;
  std::string error;
  REQUIRE(w1::rewind::load_replay_context(trace_path.string(), context, error));

  uint64_t offset = 0;
  auto mapping1 = context.find_mapping_for_address(0, 0x1000, 0x10, offset);
  REQUIRE(mapping1);
  CHECK(mapping1->image_id == 1);

  auto mapping2 = context.find_mapping_for_address(0, 0x2050, 0x10, offset);
  REQUIRE(mapping2);
  CHECK(mapping2->image_id == 2);

  auto mapping_none = context.find_mapping_for_address(0, 0x3000, 0x10, offset);
  CHECK(mapping_none == nullptr);

  fs::remove(trace_path);
}

TEST_CASE("replay context resolves overlapping mappings with latest wins") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_mapping_overlap.trace");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header();
  auto handle = open_trace(trace_path, header);
  write_basic_metadata(handle.builder, "x86_64", arch, {"pc"});

  write_image_mapping(handle.builder, 1, 0x1000, 0x200, "mod1");
  write_image_mapping(handle.builder, 2, 0x1100, 0x100, "mod2");

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::replay_context context;
  std::string error;
  REQUIRE(w1::rewind::load_replay_context(trace_path.string(), context, error));

  uint64_t offset = 0;
  auto mapping_left = context.find_mapping_for_address(0, 0x1080, 1, offset);
  REQUIRE(mapping_left);
  CHECK(mapping_left->image_id == 1);

  offset = 0;
  auto mapping_overlap = context.find_mapping_for_address(0, 0x1180, 1, offset);
  REQUIRE(mapping_overlap);
  CHECK(mapping_overlap->image_id == 2);

  fs::remove(trace_path);
}
