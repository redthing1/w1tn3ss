#include "doctest/doctest.hpp"

#include "p1ll/asmr/asmr.hpp"
#include "p1ll/engine/platform/platform.hpp"

using p1ll::asmr::context;
using p1ll::asmr::heur::code_signature;
using p1ll::asmr::heur::policy;
using p1ll::engine::platform::platform_key;

TEST_CASE("asmr assembles and disassembles x64") {
  platform_key platform{"linux", "x64"};
  auto ctx = context::for_platform(platform);
  REQUIRE(ctx.ok());

  auto bytes = ctx.value.assemble("mov eax, 1; ret", 0x1000);
  REQUIRE(bytes.ok());
  CHECK(bytes.value.size() >= 2);

  auto disasm = ctx.value.disassemble(bytes.value, 0x1000);
  REQUIRE(disasm.ok());
  REQUIRE(disasm.value.size() >= 2);
  CHECK(disasm.value.front().mnemonic == "mov");
  CHECK(disasm.value.back().mnemonic == "ret");
}

TEST_CASE("asmr assembles and disassembles x86") {
  platform_key platform{"linux", "x86"};
  auto ctx = context::for_platform(platform);
  REQUIRE(ctx.ok());

  auto bytes = ctx.value.assemble("mov eax, 1; ret", 0x2000);
  REQUIRE(bytes.ok());
  CHECK(bytes.value.size() >= 2);

  auto disasm = ctx.value.disassemble(bytes.value, 0x2000);
  REQUIRE(disasm.ok());
  REQUIRE(disasm.value.size() >= 2);
  CHECK(disasm.value.front().mnemonic == "mov");
  CHECK(disasm.value.back().mnemonic == "ret");
}

TEST_CASE("asmr assembles and disassembles arm64") {
  platform_key platform{"darwin", "arm64"};
  auto ctx = context::for_platform(platform);
  REQUIRE(ctx.ok());

  auto bytes = ctx.value.assemble("mov x0, #1; ret", 0x3000);
  REQUIRE(bytes.ok());
  CHECK(bytes.value.size() >= 4);

  auto disasm = ctx.value.disassemble(bytes.value, 0x3000);
  REQUIRE(disasm.ok());
  REQUIRE(disasm.value.size() >= 2);
  CHECK(disasm.value.back().mnemonic == "ret");
}

TEST_CASE("asmr heuristic signature masks x64 immediates") {
  platform_key platform{"linux", "x64"};
  auto ctx = context::for_platform(platform);
  REQUIRE(ctx.ok());

  auto bytes = ctx.value.assemble("mov eax, 0x11223344; ret", 0x4000);
  REQUIRE(bytes.ok());

  auto sig = code_signature(bytes.value, 0x4000, platform, policy::balanced);
  REQUIRE(sig.ok());
  CHECK(sig.value.pattern.find("??") != std::string::npos);
  CHECK(sig.value.pretty.find("//") != std::string::npos);
}

TEST_CASE("asmr heuristic strict policy keeps x64 immediates") {
  platform_key platform{"linux", "x64"};
  auto ctx = context::for_platform(platform);
  REQUIRE(ctx.ok());

  auto bytes = ctx.value.assemble("mov eax, 0x11223344; ret", 0x5000);
  REQUIRE(bytes.ok());

  auto sig = code_signature(bytes.value, 0x5000, platform, policy::strict);
  REQUIRE(sig.ok());
  CHECK(sig.value.pattern.find("??") == std::string::npos);
}

TEST_CASE("asmr heuristic signature masks arm64 immediates") {
  platform_key platform{"darwin", "arm64"};
  auto ctx = context::for_platform(platform);
  REQUIRE(ctx.ok());

  auto bytes = ctx.value.assemble("mov x0, #0x1234; ret", 0x6000);
  REQUIRE(bytes.ok());

  auto sig = code_signature(bytes.value, 0x6000, platform, policy::balanced);
  REQUIRE(sig.ok());
  CHECK(sig.value.pattern.find("??") != std::string::npos);
}
