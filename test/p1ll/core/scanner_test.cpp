#include "doctest/doctest.hpp"

#include "p1ll/engine/address_space.hpp"
#include "p1ll/engine/pattern.hpp"
#include "p1ll/engine/scanner.hpp"
#include "p1ll/engine/types.hpp"
#include "test_helpers.hpp"

#include <span>

namespace {

using p1ll::engine::buffer_address_space;
using p1ll::engine::error_code;
using p1ll::engine::parse_signature;
using p1ll::engine::scan_options;
using p1ll::engine::scanner;
using p1ll::test_helpers::make_buffer;
using p1ll::test_helpers::write_bytes;

} // namespace

TEST_CASE("scanner finds matches in buffer") {
  auto buffer = make_buffer(64, 0x90);
  write_bytes(buffer, 8, {0x48, 0x89, 0xe5});
  write_bytes(buffer, 32, {0x48, 0x89, 0xe5});

  buffer_address_space space(std::span<uint8_t>(buffer.data(), buffer.size()));
  auto parsed = parse_signature("48 89 e5");
  REQUIRE(parsed.ok());

  scanner scan(space);
  auto results = scan.scan(parsed.value, scan_options{});
  REQUIRE(results.ok());
  CHECK(results.value.size() == 2);
  CHECK(results.value[0].address == 8);
  CHECK(results.value[1].address == 32);
}

TEST_CASE("scanner respects single match option") {
  auto buffer = make_buffer(64, 0x90);
  write_bytes(buffer, 8, {0x48, 0x89, 0xe5});
  write_bytes(buffer, 32, {0x48, 0x89, 0xe5});

  buffer_address_space space(std::span<uint8_t>(buffer.data(), buffer.size()));
  auto parsed = parse_signature("48 89 e5");
  REQUIRE(parsed.ok());

  scanner scan(space);
  scan_options options;
  options.single = true;

  auto results = scan.scan(parsed.value, options);
  CHECK_FALSE(results.ok());
  CHECK(results.status_info.code == error_code::multiple_matches);
}

TEST_CASE("scanner returns not found when single match required") {
  auto buffer = make_buffer(32, 0x90);

  buffer_address_space space(std::span<uint8_t>(buffer.data(), buffer.size()));
  auto parsed = parse_signature("48 89 e5");
  REQUIRE(parsed.ok());

  scanner scan(space);
  scan_options options;
  options.single = true;

  auto results = scan.scan(parsed.value, options);
  CHECK_FALSE(results.ok());
  CHECK(results.status_info.code == error_code::not_found);
}

TEST_CASE("scanner respects max_matches") {
  auto buffer = make_buffer(64, 0x90);
  write_bytes(buffer, 8, {0x48, 0x89, 0xe5});
  write_bytes(buffer, 32, {0x48, 0x89, 0xe5});

  buffer_address_space space(std::span<uint8_t>(buffer.data(), buffer.size()));
  auto parsed = parse_signature("48 89 e5");
  REQUIRE(parsed.ok());

  scanner scan(space);
  scan_options options;
  options.max_matches = 1;

  auto results = scan.scan(parsed.value, options);
  REQUIRE(results.ok());
  CHECK(results.value.size() == 1);
}

TEST_CASE("scanner ignores invalid name filters in static buffers") {
  auto buffer = make_buffer(32, 0x90);
  write_bytes(buffer, 4, {0xde, 0xad, 0xbe, 0xef});

  buffer_address_space space(std::span<uint8_t>(buffer.data(), buffer.size()));
  auto parsed = parse_signature("de ad be ef");
  REQUIRE(parsed.ok());

  scanner scan(space);
  scan_options options;
  options.filter.name_regex = "[";

  auto results = scan.scan(parsed.value, options);
  REQUIRE(results.ok());
  CHECK(results.value.size() == 1);
}

TEST_CASE("scanner filter excludes non-executable buffers") {
  auto buffer = make_buffer(32, 0x90);
  write_bytes(buffer, 4, {0xde, 0xad, 0xbe, 0xef});

  buffer_address_space space(std::span<uint8_t>(buffer.data(), buffer.size()));
  auto parsed = parse_signature("de ad be ef");
  REQUIRE(parsed.ok());

  scanner scan(space);
  scan_options options;
  options.filter.only_executable = true;

  auto results = scan.scan(parsed.value, options);
  REQUIRE(results.ok());
  CHECK(results.value.empty());
}
