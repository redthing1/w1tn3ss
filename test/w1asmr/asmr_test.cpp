#include "doctest/doctest.hpp"

#include "w1asmr/asmr.hpp"

using w1::asmr::arch;
using w1::asmr::arch_to_string;
using w1::asmr::context;
using w1::asmr::detect_host_arch;
using w1::asmr::parse_arch;

TEST_CASE("w1asmr assembles and disassembles x64") {
  auto ctx = context::for_arch(arch::x64);
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

TEST_CASE("w1asmr assembles and disassembles x86") {
  auto ctx = context::for_arch(arch::x86);
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

TEST_CASE("w1asmr assembles and disassembles arm64") {
  auto ctx = context::for_arch(arch::arm64);
  REQUIRE(ctx.ok());

  auto bytes = ctx.value.assemble("mov x0, #1; ret", 0x3000);
  REQUIRE(bytes.ok());
  CHECK(bytes.value.size() >= 4);

  auto disasm = ctx.value.disassemble(bytes.value, 0x3000);
  REQUIRE(disasm.ok());
  REQUIRE(disasm.value.size() >= 2);
  CHECK(disasm.value.back().mnemonic == "ret");
}

TEST_CASE("w1asmr parses architecture aliases") {
  CHECK(parse_arch("x86").ok());
  CHECK(parse_arch("i386").ok());
  CHECK(parse_arch("x64").ok());
  CHECK(parse_arch("x86_64").ok());
  CHECK(parse_arch("amd64").ok());
  CHECK(parse_arch("arm64").ok());
  CHECK(parse_arch("aarch64").ok());

  CHECK(parse_arch("x86_64").value == arch::x64);
  CHECK(parse_arch("aarch64").value == arch::arm64);
  CHECK(parse_arch("i386").value == arch::x86);

  auto bad = parse_arch("mips64");
  CHECK_FALSE(bad.ok());
}

TEST_CASE("w1asmr reports host architecture") {
  auto detected = detect_host_arch();
  REQUIRE(detected.ok());
  CHECK(!arch_to_string(detected.value).empty());
}
