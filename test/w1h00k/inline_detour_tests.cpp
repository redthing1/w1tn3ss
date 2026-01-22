#include "doctest/doctest.hpp"

#include <array>
#include <string>

#include "w1base/arch_spec.hpp"
#include "w1h00k/backend/inline/inline_detour.hpp"

namespace {

w1::arch::arch_spec parse_arch_or(const char* name, const w1::arch::arch_spec& fallback) {
  w1::arch::arch_spec spec{};
  std::string error;
  if (!w1::arch::parse_arch_spec(name, spec, error)) {
    return fallback;
  }
  return spec;
}

} // namespace

TEST_CASE("w1h00k inline detour plans rel32 for x86_32") {
  auto spec = parse_arch_or("x86", w1::arch::detect_host_arch_spec());

  auto plan = w1::h00k::backend::inline_hook::plan_for(spec, 0x1000, 0x2000);
  CHECK(plan.arch == w1::h00k::backend::inline_hook::arch_kind::x86_32);
  CHECK(plan.kind == w1::h00k::backend::inline_hook::detour_kind::rel32);
  CHECK(plan.min_patch == 5);
  CHECK(plan.tail_size == 5);
}

TEST_CASE("w1h00k inline detour plans rel32 for x86_64 when near") {
  auto spec = parse_arch_or("x86_64", w1::arch::detect_host_arch_spec());

  auto plan = w1::h00k::backend::inline_hook::plan_for(spec, 0x1000, 0x2000);
  CHECK(plan.arch == w1::h00k::backend::inline_hook::arch_kind::x86_64);
  CHECK(plan.kind == w1::h00k::backend::inline_hook::detour_kind::rel32);
  CHECK(plan.min_patch == 5);
  CHECK(plan.tail_size == 14);
}

TEST_CASE("w1h00k inline detour plans absolute for x86_64 when far") {
  auto spec = parse_arch_or("x86_64", w1::arch::detect_host_arch_spec());

  const uint64_t from = 0x1000;
  const uint64_t to = from + 0x1'0000'0000ULL;
  auto plan = w1::h00k::backend::inline_hook::plan_for(spec, from, to);
  CHECK(plan.kind == w1::h00k::backend::inline_hook::detour_kind::absolute);
  CHECK(plan.min_patch == 14);
  CHECK(plan.tail_size == 14);
}

TEST_CASE("w1h00k inline detour plans absolute for arm64") {
  auto spec = parse_arch_or("arm64", w1::arch::detect_host_arch_spec());

  auto plan = w1::h00k::backend::inline_hook::plan_for(spec, 0x1000, 0x2000);
  CHECK(plan.arch == w1::h00k::backend::inline_hook::arch_kind::arm64);
  CHECK(plan.kind == w1::h00k::backend::inline_hook::detour_kind::absolute);
  CHECK(plan.min_patch == 16);
  CHECK(plan.tail_size == 16);
}

TEST_CASE("w1h00k inline detour prologue safety for arm64") {
  auto spec = parse_arch_or("arm64", w1::arch::detect_host_arch_spec());

  auto plan = w1::h00k::backend::inline_hook::plan_for(spec, 0x1000, 0x2000);
  const std::array<uint8_t, 16> ret_then_nops = {
      0xC0, 0x03, 0x5F, 0xD6, // ret
      0x1F, 0x20, 0x03, 0xD5, // nop
      0x1F, 0x20, 0x03, 0xD5, // nop
      0x1F, 0x20, 0x03, 0xD5  // nop
  };
  CHECK(w1::h00k::backend::inline_hook::prologue_safe(plan, ret_then_nops.data(), ret_then_nops.size()));

  const std::array<uint8_t, 16> ret_then_data = {
      0xC0, 0x03, 0x5F, 0xD6, // ret
      0x00, 0x00, 0x00, 0x58, // ldr x0, #0
      0x00, 0x00, 0x00, 0x58, // ldr x0, #0
      0x00, 0x00, 0x00, 0x58  // ldr x0, #0
  };
  CHECK_FALSE(w1::h00k::backend::inline_hook::prologue_safe(plan, ret_then_data.data(), ret_then_data.size()));
}
