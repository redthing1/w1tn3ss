#include <array>
#include <cstddef>
#include <cstdint>

#include "doctest/doctest.hpp"

#include "w1replay/gdb/value_codec.hpp"

TEST_CASE("gdb value codec encodes big endian values") {
  std::array<std::byte, 4> out{};
  REQUIRE(w1replay::gdb::encode_uint64(0x11223344u, out.size(), out, w1replay::gdb::endian::big));
  CHECK(out[0] == std::byte{0x11});
  CHECK(out[1] == std::byte{0x22});
  CHECK(out[2] == std::byte{0x33});
  CHECK(out[3] == std::byte{0x44});
}

TEST_CASE("gdb value codec encodes little endian values") {
  std::array<std::byte, 4> out{};
  REQUIRE(w1replay::gdb::encode_uint64(0x11223344u, out.size(), out, w1replay::gdb::endian::little));
  CHECK(out[0] == std::byte{0x44});
  CHECK(out[1] == std::byte{0x33});
  CHECK(out[2] == std::byte{0x22});
  CHECK(out[3] == std::byte{0x11});
}
