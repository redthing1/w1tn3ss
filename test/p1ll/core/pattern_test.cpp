#include "doctest/doctest.hpp"

#include "p1ll/engine/pattern.hpp"

namespace {

using p1ll::engine::error_code;
using p1ll::engine::parse_patch;
using p1ll::engine::parse_signature;

} // namespace

TEST_CASE("pattern parsing handles valid signatures") {
  auto parsed = parse_signature("48 89 e5 ?? 90");
  CHECK(parsed.ok());
  CHECK(parsed.value.bytes.size() == 5);
  CHECK(parsed.value.mask.size() == 5);
  CHECK(parsed.value.bytes[0] == 0x48);
  CHECK(parsed.value.bytes[1] == 0x89);
  CHECK(parsed.value.bytes[2] == 0xe5);
  CHECK(parsed.value.bytes[3] == 0x00);
  CHECK(parsed.value.bytes[4] == 0x90);
  CHECK(parsed.value.mask[3] == 0);
}

TEST_CASE("pattern parsing rejects invalid signatures") {
  auto parsed = parse_signature("zz 90");
  CHECK_FALSE(parsed.ok());
  CHECK(parsed.status_info.code == error_code::invalid_pattern);
}

TEST_CASE("pattern parsing normalizes whitespace") {
  auto parsed = parse_signature("  48\t89  e5\n90 ");
  CHECK(parsed.ok());
  CHECK(parsed.value.bytes.size() == 4);
}

TEST_CASE("pattern parsing handles patches") {
  auto parsed = parse_patch("ff ?? 0a");
  CHECK(parsed.ok());
  CHECK(parsed.value.bytes.size() == 3);
  CHECK(parsed.value.mask[1] == 0);
}
