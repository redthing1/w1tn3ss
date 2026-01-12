#include "doctest/doctest.hpp"

#include "p1ll/engine/pattern.hpp"
#include "p1ll/engine/pattern_matcher.hpp"

#include <vector>

namespace {

using p1ll::engine::parse_signature;
using p1ll::engine::pattern_matcher;

} // namespace

TEST_CASE("pattern matcher finds exact matches") {
  std::vector<uint8_t> data = {0x90, 0x48, 0x89, 0xe5, 0x90};
  auto parsed = parse_signature("48 89 e5");
  REQUIRE(parsed.ok());

  pattern_matcher matcher(parsed.value);
  auto matches = matcher.search(data.data(), data.size());
  REQUIRE(matches.size() == 1);
  CHECK(matches[0] == 1);
}

TEST_CASE("pattern matcher supports wildcards") {
  std::vector<uint8_t> data = {0x48, 0x89, 0xe5, 0x12, 0x90};
  auto parsed = parse_signature("48 89 ?? 12 90");
  REQUIRE(parsed.ok());

  pattern_matcher matcher(parsed.value);
  auto matches = matcher.search(data.data(), data.size());
  REQUIRE(matches.size() == 1);
  CHECK(matches[0] == 0);
}

TEST_CASE("pattern matcher handles overlapping matches") {
  std::vector<uint8_t> data = {0x90, 0x90, 0x90};
  auto parsed = parse_signature("90 90");
  REQUIRE(parsed.ok());

  pattern_matcher matcher(parsed.value);
  auto matches = matcher.search(data.data(), data.size());
  REQUIRE(matches.size() == 2);
  CHECK(matches[0] == 0);
  CHECK(matches[1] == 1);
}

TEST_CASE("pattern matcher reports single match only when unique") {
  std::vector<uint8_t> data = {0x90, 0x90, 0x90};
  auto parsed = parse_signature("90 90");
  REQUIRE(parsed.ok());

  pattern_matcher matcher(parsed.value);
  auto match = matcher.search_single(data.data(), data.size());
  CHECK_FALSE(match.has_value());
}
