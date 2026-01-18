#include "doctest/doctest.hpp"

#include "p1ll/heur/code_signature.hpp"
#include "w1asmr/asmr.hpp"

using p1ll::engine::platform::platform_key;
using p1ll::heur::code_signature;
using p1ll::heur::policy;
using w1::asmr::arch;
using w1::asmr::context;

TEST_CASE("p1ll heuristic signature masks x64 immediates") {
  auto ctx = context::for_arch(arch::x64);
  REQUIRE(ctx.ok());

  auto bytes = ctx.value.assemble("mov eax, 0x11223344; ret", 0x4000);
  REQUIRE(bytes.ok());

  platform_key platform{"linux", "x64"};
  auto sig = code_signature(bytes.value, 0x4000, platform, policy::balanced);
  REQUIRE(sig.ok());
  CHECK(sig.value.pattern.find("??") != std::string::npos);
  CHECK(sig.value.pretty.find("//") != std::string::npos);
}

TEST_CASE("p1ll heuristic strict policy keeps x64 immediates") {
  auto ctx = context::for_arch(arch::x64);
  REQUIRE(ctx.ok());

  auto bytes = ctx.value.assemble("mov eax, 0x11223344; ret", 0x5000);
  REQUIRE(bytes.ok());

  platform_key platform{"linux", "x64"};
  auto sig = code_signature(bytes.value, 0x5000, platform, policy::strict);
  REQUIRE(sig.ok());
  CHECK(sig.value.pattern.find("??") == std::string::npos);
}

TEST_CASE("p1ll heuristic signature masks arm64 immediates") {
  auto ctx = context::for_arch(arch::arm64);
  REQUIRE(ctx.ok());

  auto bytes = ctx.value.assemble("mov x0, #0x1234; ret", 0x6000);
  REQUIRE(bytes.ok());

  platform_key platform{"darwin", "arm64"};
  auto sig = code_signature(bytes.value, 0x6000, platform, policy::balanced);
  REQUIRE(sig.ok());
  CHECK(sig.value.pattern.find("??") != std::string::npos);
}
