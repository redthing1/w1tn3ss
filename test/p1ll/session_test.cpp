#include "doctest/doctest.hpp"

#include "p1ll/engine/session.hpp"
#include "p1ll/engine/types.hpp"
#include "test_helpers.hpp"

#include <span>

namespace {

using p1ll::engine::error_code;
using p1ll::engine::session;
using p1ll::test_helpers::make_buffer;
using p1ll::test_helpers::write_bytes;

} // namespace

TEST_CASE("session scan rejects invalid patterns") {
  auto buffer = make_buffer(16, 0x90);
  auto sess = session::for_buffer(std::span<uint8_t>(buffer.data(), buffer.size()));

  p1ll::engine::scan_options options;
  auto result = sess.scan("zz", options);
  CHECK_FALSE(result.ok());
  CHECK(result.status.code == error_code::invalid_pattern);
}

TEST_CASE("session scan returns matches for valid patterns") {
  auto buffer = make_buffer(16, 0x90);
  write_bytes(buffer, 4, {0x48, 0x89, 0xe5});
  auto sess = session::for_buffer(std::span<uint8_t>(buffer.data(), buffer.size()));

  p1ll::engine::scan_options options;
  auto result = sess.scan("48 89 e5", options);
  REQUIRE(result.ok());
  CHECK(result.value.size() == 1);
  CHECK(result.value[0].address == 4);
}
