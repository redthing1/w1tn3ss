#include <array>
#include <cstddef>
#include <vector>

#include "doctest/doctest.hpp"

#include "w1replay/module_image.hpp"

TEST_CASE("module_image reads file-backed bytes") {
  w1replay::image_layout layout;
  layout.link_base = 0x1000;
  std::array<std::byte, 4> bytes = {std::byte{0x1}, std::byte{0x2}, std::byte{0x3}, std::byte{0x4}};
  w1replay::image_range range{};
  range.va_start = 0x1000;
  range.mem_size = 4;
  range.file_bytes = std::span<const std::byte>(bytes.data(), bytes.size());
  layout.ranges = {range};

  auto result = w1replay::read_image_bytes(layout, 0, 4);
  CHECK(result.error.empty());
  CHECK(result.complete);
  CHECK(result.bytes.size() == 4);
  CHECK(result.known.size() == 4);
  CHECK(result.bytes[0] == std::byte{0x1});
  CHECK(result.bytes[3] == std::byte{0x4});
}

TEST_CASE("module_image zero-fills bss") {
  w1replay::image_layout layout;
  layout.link_base = 0x2000;
  std::array<std::byte, 4> bytes = {std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}};
  w1replay::image_range range{};
  range.va_start = 0x2000;
  range.mem_size = 8;
  range.file_bytes = std::span<const std::byte>(bytes.data(), bytes.size());
  layout.ranges = {range};

  auto result = w1replay::read_image_bytes(layout, 0, 8);
  CHECK(result.error.empty());
  CHECK(result.complete);
  CHECK(result.bytes.size() == 8);
  CHECK(result.bytes[0] == std::byte{0xAA});
  CHECK(result.bytes[3] == std::byte{0xDD});
  CHECK(result.bytes[4] == std::byte{0x00});
  CHECK(result.bytes[7] == std::byte{0x00});
}

TEST_CASE("module_image tracks unknown ranges") {
  w1replay::image_layout layout;
  layout.link_base = 0x3000;
  std::array<std::byte, 2> bytes = {std::byte{0x10}, std::byte{0x20}};
  w1replay::image_range range{};
  range.va_start = 0x3000;
  range.mem_size = 2;
  range.file_bytes = std::span<const std::byte>(bytes.data(), bytes.size());
  layout.ranges = {range};

  auto result = w1replay::read_image_bytes(layout, 0, 4);
  CHECK(result.error.empty());
  CHECK(!result.complete);
  CHECK(result.known.size() == 4);
  CHECK(result.known[0] == 1);
  CHECK(result.known[1] == 1);
  CHECK(result.known[2] == 0);
  CHECK(result.known[3] == 0);
}

TEST_CASE("module_image stitches across ranges") {
  w1replay::image_layout layout;
  layout.link_base = 0x4000;
  std::array<std::byte, 2> bytes_a = {std::byte{0x1}, std::byte{0x2}};
  std::array<std::byte, 2> bytes_b = {std::byte{0x3}, std::byte{0x4}};
  w1replay::image_range range_a{};
  range_a.va_start = 0x4000;
  range_a.mem_size = 2;
  range_a.file_bytes = std::span<const std::byte>(bytes_a.data(), bytes_a.size());
  w1replay::image_range range_b{};
  range_b.va_start = 0x4002;
  range_b.mem_size = 2;
  range_b.file_bytes = std::span<const std::byte>(bytes_b.data(), bytes_b.size());
  layout.ranges = {range_a, range_b};

  auto result = w1replay::read_image_bytes(layout, 0, 4);
  CHECK(result.error.empty());
  CHECK(result.complete);
  CHECK(result.bytes[0] == std::byte{0x1});
  CHECK(result.bytes[3] == std::byte{0x4});
}
