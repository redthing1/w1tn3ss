#include "doctest/doctest.hpp"

#include "w1asmr/asmr.hpp"

using w1::asmr::asm_context;
using w1::asmr::detect_host_arch_spec;
using w1::asmr::disasm_context;
using w1::asmr::parse_arch_spec;

TEST_CASE("w1asmr assembles and disassembles x64") {
  auto spec = parse_arch_spec("x64");
  REQUIRE(spec.ok());

  auto asm_ctx = asm_context::for_arch(spec.value);
  REQUIRE(asm_ctx.ok());
  auto dis_ctx = disasm_context::for_arch(spec.value);
  REQUIRE(dis_ctx.ok());

  auto bytes = asm_ctx.value.assemble("mov eax, 1; ret", 0x1000);
  REQUIRE(bytes.ok());
  CHECK(bytes.value.size() >= 2);

  auto disasm = dis_ctx.value.disassemble(bytes.value, 0x1000);
  REQUIRE(disasm.ok());
  REQUIRE(disasm.value.size() >= 2);
  CHECK(disasm.value.front().mnemonic == "mov");
  CHECK(disasm.value.back().mnemonic == "ret");
}

TEST_CASE("w1asmr assembles and disassembles x86") {
  auto spec = parse_arch_spec("x86");
  REQUIRE(spec.ok());

  auto asm_ctx = asm_context::for_arch(spec.value);
  REQUIRE(asm_ctx.ok());
  auto dis_ctx = disasm_context::for_arch(spec.value);
  REQUIRE(dis_ctx.ok());

  auto bytes = asm_ctx.value.assemble("mov eax, 1; ret", 0x2000);
  REQUIRE(bytes.ok());
  CHECK(bytes.value.size() >= 2);

  auto disasm = dis_ctx.value.disassemble(bytes.value, 0x2000);
  REQUIRE(disasm.ok());
  REQUIRE(disasm.value.size() >= 2);
  CHECK(disasm.value.front().mnemonic == "mov");
  CHECK(disasm.value.back().mnemonic == "ret");
}

TEST_CASE("w1asmr assembles and disassembles arm64") {
  auto spec = parse_arch_spec("arm64");
  REQUIRE(spec.ok());

  auto asm_ctx = asm_context::for_arch(spec.value);
  REQUIRE(asm_ctx.ok());
  auto dis_ctx = disasm_context::for_arch(spec.value);
  REQUIRE(dis_ctx.ok());

  auto bytes = asm_ctx.value.assemble("mov x0, #1; ret", 0x3000);
  REQUIRE(bytes.ok());
  CHECK(bytes.value.size() >= 4);

  auto disasm = dis_ctx.value.disassemble(bytes.value, 0x3000);
  REQUIRE(disasm.ok());
  REQUIRE(disasm.value.size() >= 2);
  CHECK(disasm.value.back().mnemonic == "ret");
}

TEST_CASE("w1asmr disassembles arm32 and thumb") {
  auto arm_spec = parse_arch_spec("arm");
  REQUIRE(arm_spec.ok());
  auto arm_ctx = disasm_context::for_arch(arm_spec.value);
  REQUIRE(arm_ctx.ok());

  std::vector<uint8_t> arm_bytes = {0x01, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1};
  auto arm_disasm = arm_ctx.value.disassemble(arm_bytes, 0x4000);
  REQUIRE(arm_disasm.ok());
  CHECK_FALSE(arm_disasm.value.empty());

  auto thumb_spec = parse_arch_spec("thumb");
  REQUIRE(thumb_spec.ok());
  auto thumb_ctx = disasm_context::for_arch(thumb_spec.value);
  REQUIRE(thumb_ctx.ok());

  std::vector<uint8_t> thumb_bytes = {0x01, 0x20, 0x70, 0x47};
  auto thumb_disasm = thumb_ctx.value.disassemble(thumb_bytes, 0x5000);
  REQUIRE(thumb_disasm.ok());
  CHECK_FALSE(thumb_disasm.value.empty());
}

TEST_CASE("w1asmr disassembles riscv64") {
  auto spec = parse_arch_spec("riscv64");
  REQUIRE(spec.ok());

  auto dis_ctx = disasm_context::for_arch(spec.value);
  REQUIRE(dis_ctx.ok());

  std::vector<uint8_t> bytes = {0x13, 0x00, 0x00, 0x00};
  auto disasm = dis_ctx.value.disassemble(bytes, 0x6000);
  REQUIRE(disasm.ok());
  CHECK_FALSE(disasm.value.empty());
}

TEST_CASE("w1asmr reports unsupported assembly targets") {
  auto spec = parse_arch_spec("systemz");
  REQUIRE(spec.ok());

  auto asm_ctx = asm_context::for_arch(spec.value);
  CHECK_FALSE(asm_ctx.ok());
  CHECK(asm_ctx.status_info.code == w1::asmr::error_code::unsupported);
}

TEST_CASE("w1asmr parses architecture aliases") {
  CHECK(parse_arch_spec("x86").ok());
  CHECK(parse_arch_spec("i386").ok());
  CHECK(parse_arch_spec("x64").ok());
  CHECK(parse_arch_spec("x86_64").ok());
  CHECK(parse_arch_spec("amd64").ok());
  CHECK(parse_arch_spec("arm64").ok());
  CHECK(parse_arch_spec("aarch64").ok());
  CHECK(parse_arch_spec("thumb:le").ok());

  CHECK(parse_arch_spec("x86_64").value.arch_mode == w1::arch::mode::x86_64);
  CHECK(parse_arch_spec("aarch64").value.arch_mode == w1::arch::mode::aarch64);
  CHECK(parse_arch_spec("i386").value.arch_mode == w1::arch::mode::x86_32);

  auto bad = parse_arch_spec("mystery");
  CHECK_FALSE(bad.ok());
}

TEST_CASE("w1asmr reports host architecture") {
  auto detected = detect_host_arch_spec();
  REQUIRE(detected.ok());
  CHECK(detected.value.arch_mode != w1::arch::mode::unknown);
}
