#include <array>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "doctest/doctest.hpp"

#include "w1replay/modules/composite_image_provider.hpp"
#include "w1replay/modules/file_image_reader.hpp"
#include "w1replay/modules/image_layout_provider.hpp"
#include "w1replay/modules/path_resolver.hpp"
#include "w1rewind/replay/replay_context.hpp"

namespace {

std::filesystem::path make_temp_path() {
  auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  auto name = std::string("w1r_layout_test_") + std::to_string(now) + ".bin";
  return std::filesystem::temp_directory_path() / name;
}

struct test_layout_provider final : public w1replay::image_layout_provider {
  bool called = false;
  uint64_t file_size = 0;
  std::string identity;
  std::optional<uint32_t> age;

  bool build_layout(
      const w1::rewind::image_record& /*image*/, const w1::rewind::image_metadata_record* /*metadata*/,
      const std::string& path, w1replay::image_layout& layout, w1replay::image_layout_identity* identity_out,
      std::string& /*error*/
  ) override {
    called = true;
    layout = w1replay::image_layout{};
    layout.link_base = 0x2000;
    w1replay::image_range range{};
    range.va_start = 0x2000;
    range.mem_size = file_size;
    range.file_offset = 0;
    range.file_size = file_size;
    layout.ranges.push_back(std::move(range));
    layout.file_reader = std::make_shared<w1replay::file_image_reader>(path, file_size);
    if (identity_out) {
      identity_out->identity = identity;
      identity_out->age = age;
    }
    return true;
  }
};

} // namespace

TEST_CASE("composite_image_provider reads file bytes using metadata segments") {
  std::filesystem::path temp_path = make_temp_path();

  {
    std::ofstream out(temp_path, std::ios::binary | std::ios::out | std::ios::trunc);
    REQUIRE(out.is_open());
    std::array<uint8_t, 8> bytes = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    REQUIRE(out.good());
  }

  w1::rewind::replay_context context{};
  w1::rewind::image_record image{};
  image.image_id = 1;
  image.flags = w1::rewind::image_flag_file_backed;
  image.name = "rom.bin";
  image.path = "rom.bin";
  context.images.push_back(image);
  context.images_by_id[1] = 0;

  w1::rewind::image_metadata_record meta{};
  meta.image_id = 1;
  meta.flags = w1::rewind::image_meta_has_link_base | w1::rewind::image_meta_has_segments;
  meta.link_base = 0x1000;
  meta.segments.push_back({"SEG", 0x1000, 8, 0, 8, 0});
  context.image_metadata_by_id[1] = meta;

  auto resolver = w1replay::make_image_path_resolver({"rom.bin=" + temp_path.string()}, {});
  w1replay::composite_image_provider_config config{};
  config.context = &context;
  config.resolver = resolver.get();
  w1replay::composite_image_provider provider(config);

  auto result = provider.read_image_bytes(context.images[0], 0, 8);
  CHECK(result.error.empty());
  CHECK(result.complete);
  REQUIRE(result.bytes.size() == 8);
  CHECK(result.bytes[0] == std::byte{0x1});
  CHECK(result.bytes[7] == std::byte{0x8});

  std::error_code ec;
  std::filesystem::remove(temp_path, ec);
}

TEST_CASE("composite_image_provider falls back to layout provider when metadata is missing") {
  std::filesystem::path temp_path = make_temp_path();

  {
    std::ofstream out(temp_path, std::ios::binary | std::ios::out | std::ios::trunc);
    REQUIRE(out.is_open());
    std::array<uint8_t, 4> bytes = {0xaa, 0xbb, 0xcc, 0xdd};
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    REQUIRE(out.good());
  }

  w1::rewind::replay_context context{};
  w1::rewind::image_record image{};
  image.image_id = 2;
  image.flags = w1::rewind::image_flag_file_backed;
  image.name = "dummy.bin";
  image.path = "dummy.bin";
  context.images.push_back(image);
  context.images_by_id[2] = 0;

  auto layout_provider = std::make_shared<test_layout_provider>();
  layout_provider->file_size = 4;
  auto resolver = w1replay::make_image_path_resolver({"dummy.bin=" + temp_path.string()}, {});
  w1replay::composite_image_provider_config config{};
  config.context = &context;
  config.resolver = resolver.get();
  config.layout_provider = layout_provider;
  w1replay::composite_image_provider provider(config);

  auto result = provider.read_image_bytes(context.images[0], 0, 4);
  CHECK(result.error.empty());
  CHECK(result.complete);
  CHECK(layout_provider->called);
  REQUIRE(result.bytes.size() == 4);
  CHECK(result.bytes[0] == std::byte{0xaa});
  CHECK(result.bytes[3] == std::byte{0xdd});

  std::error_code ec;
  std::filesystem::remove(temp_path, ec);
}

TEST_CASE("composite_image_provider fails without metadata and layout provider") {
  std::filesystem::path temp_path = make_temp_path();

  {
    std::ofstream out(temp_path, std::ios::binary | std::ios::out | std::ios::trunc);
    REQUIRE(out.is_open());
    std::array<uint8_t, 2> bytes = {0x11, 0x22};
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    REQUIRE(out.good());
  }

  w1::rewind::replay_context context{};
  w1::rewind::image_record image{};
  image.image_id = 5;
  image.flags = w1::rewind::image_flag_file_backed;
  image.name = "missing.bin";
  image.path = "missing.bin";
  context.images.push_back(image);
  context.images_by_id[5] = 0;

  auto resolver = w1replay::make_image_path_resolver({"missing.bin=" + temp_path.string()}, {});
  w1replay::composite_image_provider_config config{};
  config.context = &context;
  config.resolver = resolver.get();
  w1replay::composite_image_provider provider(config);

  auto result = provider.read_image_bytes(context.images[0], 0, 2);
  CHECK(result.error == "image metadata missing");
  CHECK(!result.complete);

  std::error_code ec;
  std::filesystem::remove(temp_path, ec);
}

TEST_CASE("composite_image_provider rejects mismatched layout identity") {
  std::filesystem::path temp_path = make_temp_path();
  {
    std::ofstream out(temp_path, std::ios::binary | std::ios::out | std::ios::trunc);
    REQUIRE(out.is_open());
    std::array<uint8_t, 1> bytes = {0x1};
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    REQUIRE(out.good());
  }

  w1::rewind::replay_context context{};
  w1::rewind::image_record image{};
  image.image_id = 3;
  image.flags = w1::rewind::image_flag_file_backed;
  image.name = "dummy.bin";
  image.path = "dummy.bin";
  image.identity = "expected-id";
  context.images.push_back(image);
  context.images_by_id[3] = 0;

  auto layout_provider = std::make_shared<test_layout_provider>();
  layout_provider->file_size = 1;
  layout_provider->identity = "other-id";
  auto resolver = w1replay::make_image_path_resolver({"dummy.bin=" + temp_path.string()}, {});
  w1replay::composite_image_provider_config config{};
  config.context = &context;
  config.resolver = resolver.get();
  config.layout_provider = layout_provider;
  w1replay::composite_image_provider provider(config);

  auto result = provider.read_image_bytes(context.images[0], 0, 4);
  CHECK_FALSE(result.error.empty());
  CHECK(result.error == "image identity mismatch");

  std::error_code ec;
  std::filesystem::remove(temp_path, ec);
}
