#include "doctest/doctest.hpp"

#include "p1ll/engine/platform/platform.hpp"

namespace {

using p1ll::engine::platform::any_platform_matches;
using p1ll::engine::platform::detect_platform;
using p1ll::engine::platform::parse_platform;
using p1ll::engine::platform::platform_key;
using p1ll::engine::platform::platform_matches;

} // namespace

TEST_CASE("platform parsing handles wildcards") {
  auto parsed = parse_platform("*");
  REQUIRE(parsed.ok());
  CHECK(parsed.value.os == "*");
  CHECK(parsed.value.arch == "*");
}

TEST_CASE("platform parsing handles os-only selectors") {
  auto parsed = parse_platform("darwin");
  REQUIRE(parsed.ok());
  CHECK(parsed.value.os == "darwin");
  CHECK(parsed.value.arch == "*");
}

TEST_CASE("platform parsing treats blank as wildcard") {
  auto parsed = parse_platform(" ");
  REQUIRE(parsed.ok());
  CHECK(parsed.value.os == "*");
  CHECK(parsed.value.arch == "*");
}

TEST_CASE("platform matching respects wildcards") {
  platform_key target{"darwin", "arm64"};
  CHECK(platform_matches("*", target));
  CHECK(platform_matches("darwin:*", target));
  CHECK_FALSE(platform_matches("linux:x64", target));
}

TEST_CASE("any_platform_matches accepts empty list") {
  platform_key target{"darwin", "arm64"};
  CHECK(any_platform_matches({}, target));
}

TEST_CASE("detect_platform returns non-empty values") {
  auto detected = detect_platform();
  CHECK_FALSE(detected.os.empty());
  CHECK_FALSE(detected.arch.empty());
}
