#include <filesystem>

#include "doctest/doctest.hpp"

#include "w1rewind/replay/replay_context.hpp"
#include "w1rewind/rewind_test_helpers.hpp"

TEST_CASE("replay context prefers latest image record") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_image_updates.trace");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header();
  auto handle = open_trace(trace_path, header);

  write_basic_metadata(handle.builder, "x86_64", arch, minimal_registers(arch));

  w1::rewind::image_record image1{};
  image1.image_id = 1;
  image1.kind = "test";
  image1.name = "module_a";
  image1.identity = "module_a";
  REQUIRE(handle.builder.emit_image(image1));

  w1::rewind::image_record image2{};
  image2.image_id = 1;
  image2.kind = "test";
  image2.name = "module_b";
  image2.identity = "module_b";
  REQUIRE(handle.builder.emit_image(image2));

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::replay_context context;
  std::string error;
  REQUIRE(w1::rewind::load_replay_context(trace_path.string(), context, error));

  const auto* image = context.find_image(1);
  REQUIRE(image != nullptr);
  CHECK(image->name == "module_b");

  fs::remove(trace_path);
}
