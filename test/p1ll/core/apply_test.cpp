#include "doctest/doctest.hpp"

#include "p1ll/engine/address_space.hpp"
#include "p1ll/engine/apply.hpp"
#include "p1ll/engine/types.hpp"
#include "test_helpers.hpp"

#include <span>

namespace {

using p1ll::engine::apply_options;
using p1ll::engine::apply_plan;
using p1ll::engine::buffer_address_space;
using p1ll::engine::error_code;
using p1ll::engine::plan_entry;
using p1ll::test_helpers::make_buffer;
using p1ll::test_helpers::write_bytes;

} // namespace

TEST_CASE("apply writes masked bytes") {
  auto buffer = make_buffer(16, 0x00);
  buffer_address_space space(std::span<uint8_t>(buffer.data(), buffer.size()));

  plan_entry entry;
  entry.address = 4;
  entry.patch_bytes = {0xaa, 0xbb, 0xcc};
  entry.patch_mask = {1, 0, 1};
  entry.spec.required = true;

  auto result = apply_plan(space, {entry}, apply_options{});
  REQUIRE(result.ok());
  CHECK(result.value.success);
  CHECK(buffer[4] == 0xaa);
  CHECK(buffer[5] == 0x00);
  CHECK(buffer[6] == 0xcc);
}

TEST_CASE("apply returns error for invalid address") {
  auto buffer = make_buffer(8, 0x90);
  buffer_address_space space(std::span<uint8_t>(buffer.data(), buffer.size()));

  plan_entry entry;
  entry.address = 16;
  entry.patch_bytes = {0x11, 0x22};
  entry.patch_mask = {1, 1};
  entry.spec.required = true;

  auto result = apply_plan(space, {entry}, apply_options{});
  CHECK_FALSE(result.ok());
  CHECK(result.status.code == error_code::not_found);
}

TEST_CASE("apply reports optional failure without aborting") {
  auto buffer = make_buffer(8, 0x90);
  buffer_address_space space(std::span<uint8_t>(buffer.data(), buffer.size()));

  plan_entry required_entry;
  required_entry.address = 2;
  required_entry.patch_bytes = {0x11, 0x22};
  required_entry.patch_mask = {1, 1};
  required_entry.spec.required = true;

  plan_entry optional_entry;
  optional_entry.address = 32;
  optional_entry.patch_bytes = {0x33, 0x44};
  optional_entry.patch_mask = {1, 1};
  optional_entry.spec.required = false;

  auto result = apply_plan(space, {required_entry, optional_entry}, apply_options{});
  REQUIRE(result.ok());
  CHECK_FALSE(result.value.success);
  CHECK(result.value.applied == 1);
  CHECK(result.value.failed == 1);
  CHECK(buffer[2] == 0x11);
  CHECK(buffer[3] == 0x22);
}

TEST_CASE("apply skips writes for empty masks") {
  auto buffer = make_buffer(8, 0x90);
  buffer_address_space space(std::span<uint8_t>(buffer.data(), buffer.size()));

  plan_entry entry;
  entry.address = 1;
  entry.patch_bytes = {0xff, 0xee};
  entry.patch_mask = {0, 0};
  entry.spec.required = true;

  auto result = apply_plan(space, {entry}, apply_options{});
  REQUIRE(result.ok());
  CHECK(result.value.success);
  CHECK(buffer[1] == 0x90);
  CHECK(buffer[2] == 0x90);
}
