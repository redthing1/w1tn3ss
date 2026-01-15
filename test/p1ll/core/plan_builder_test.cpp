#include "doctest/doctest.hpp"

#include "p1ll/engine/session.hpp"
#include "p1ll/engine/types.hpp"
#include "p1ll/engine/platform/platform.hpp"
#include "test_helpers.hpp"

#include <span>

namespace {

using p1ll::engine::error_code;
using p1ll::engine::patch_spec;
using p1ll::engine::recipe;
using p1ll::engine::scan_options;
using p1ll::engine::session;
using p1ll::engine::signature_spec;
using p1ll::engine::platform::platform_key;
using p1ll::test_helpers::make_buffer;
using p1ll::test_helpers::write_bytes;

} // namespace

TEST_CASE("plan builder produces entries for required patches") {
  auto buffer = make_buffer(64, 0x90);
  write_bytes(buffer, 8, {0xde, 0xad, 0xbe, 0xef});
  write_bytes(buffer, 24, {0x48, 0x89, 0xe5});

  signature_spec validation;
  validation.pattern = "de ad be ef";
  validation.options.single = true;

  patch_spec patch;
  patch.signature.pattern = "48 89 e5";
  patch.signature.options.single = true;
  patch.patch = "11 22 33";
  patch.required = true;

  recipe plan_recipe;
  plan_recipe.name = "basic";
  plan_recipe.validations.push_back(validation);
  plan_recipe.patches.push_back(patch);

  auto sess = session::for_buffer(std::span<uint8_t>(buffer.data(), buffer.size()));
  auto plan = sess.plan(plan_recipe);
  REQUIRE(plan.ok());
  REQUIRE(plan.value.size() == 1);
  CHECK(plan.value[0].address == 24);
  CHECK(plan.value[0].patch_bytes.size() == 3);
  CHECK(plan.value[0].patch_mask.size() == 3);
}

TEST_CASE("plan builder skips optional missing patches") {
  auto buffer = make_buffer(64, 0x90);
  write_bytes(buffer, 16, {0x48, 0x89, 0xe5});

  patch_spec required_patch;
  required_patch.signature.pattern = "48 89 e5";
  required_patch.signature.options.single = true;
  required_patch.patch = "11 22 33";
  required_patch.required = true;

  patch_spec optional_patch;
  optional_patch.signature.pattern = "ff ee dd";
  optional_patch.signature.options.single = true;
  optional_patch.patch = "aa bb cc";
  optional_patch.required = false;

  recipe plan_recipe;
  plan_recipe.patches.push_back(required_patch);
  plan_recipe.patches.push_back(optional_patch);

  auto sess = session::for_buffer(std::span<uint8_t>(buffer.data(), buffer.size()));
  auto plan = sess.plan(plan_recipe);
  REQUIRE(plan.ok());
  CHECK(plan.value.size() == 1);
}

TEST_CASE("plan builder reports missing required validations") {
  auto buffer = make_buffer(32, 0x90);

  signature_spec validation;
  validation.pattern = "de ad be ef";
  validation.options.single = true;
  validation.required = true;

  patch_spec patch;
  patch.signature.pattern = "48 89 e5";
  patch.signature.options.single = true;
  patch.patch = "11 22 33";
  patch.required = true;

  recipe plan_recipe;
  plan_recipe.validations.push_back(validation);
  plan_recipe.patches.push_back(patch);

  auto sess = session::for_buffer(std::span<uint8_t>(buffer.data(), buffer.size()));
  auto plan = sess.plan(plan_recipe);
  CHECK_FALSE(plan.ok());
  CHECK(plan.status.code == error_code::not_found);
}

TEST_CASE("plan builder enforces platform selectors") {
  auto buffer = make_buffer(32, 0x90);
  write_bytes(buffer, 4, {0x48, 0x89, 0xe5});

  patch_spec patch;
  patch.signature.pattern = "48 89 e5";
  patch.signature.options.single = true;
  patch.patch = "11 22 33";

  recipe plan_recipe;
  plan_recipe.platforms.push_back("linux:x64");
  plan_recipe.patches.push_back(patch);

  platform_key target{"darwin", "arm64"};
  auto sess = session::for_buffer(std::span<uint8_t>(buffer.data(), buffer.size()), target);
  auto plan = sess.plan(plan_recipe);
  CHECK_FALSE(plan.ok());
  CHECK(plan.status.code == error_code::platform_mismatch);
}

TEST_CASE("plan builder detects overlapping patches") {
  auto buffer = make_buffer(32, 0x90);
  write_bytes(buffer, 8, {0x48, 0x89, 0xe5});

  patch_spec patch_a;
  patch_a.signature.pattern = "48 89 e5";
  patch_a.signature.options.single = true;
  patch_a.patch = "11 22 33";
  patch_a.offset = 0;

  patch_spec patch_b;
  patch_b.signature.pattern = "48 89 e5";
  patch_b.signature.options.single = true;
  patch_b.patch = "aa bb cc";
  patch_b.offset = 1;

  recipe plan_recipe;
  plan_recipe.patches.push_back(patch_a);
  plan_recipe.patches.push_back(patch_b);

  auto sess = session::for_buffer(std::span<uint8_t>(buffer.data(), buffer.size()));
  auto plan = sess.plan(plan_recipe);
  CHECK_FALSE(plan.ok());
  CHECK(plan.status.code == error_code::overlap);
}

TEST_CASE("plan builder rejects invalid patch patterns") {
  auto buffer = make_buffer(32, 0x90);
  write_bytes(buffer, 4, {0x48, 0x89, 0xe5});

  patch_spec patch;
  patch.signature.pattern = "48 89 e5";
  patch.signature.options.single = true;
  patch.patch = "zz";
  patch.required = true;

  recipe plan_recipe;
  plan_recipe.patches.push_back(patch);

  auto sess = session::for_buffer(std::span<uint8_t>(buffer.data(), buffer.size()));
  auto plan = sess.plan(plan_recipe);
  CHECK_FALSE(plan.ok());
  CHECK(plan.status.code == error_code::invalid_pattern);
}

TEST_CASE("plan builder detects offset underflow") {
  auto buffer = make_buffer(32, 0x90);
  write_bytes(buffer, 2, {0x48, 0x89, 0xe5});

  patch_spec patch;
  patch.signature.pattern = "48 89 e5";
  patch.signature.options.single = true;
  patch.patch = "11 22 33";
  patch.offset = -8;

  recipe plan_recipe;
  plan_recipe.patches.push_back(patch);

  auto sess = session::for_buffer(std::span<uint8_t>(buffer.data(), buffer.size()));
  auto plan = sess.plan(plan_recipe);
  CHECK_FALSE(plan.ok());
  CHECK(plan.status.code == error_code::invalid_argument);
}
