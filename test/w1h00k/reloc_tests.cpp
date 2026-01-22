#include "doctest/doctest.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "w1asmr/asmr.hpp"
#include "w1base/arch_spec.hpp"
#include "w1h00k/reloc/relocator.hpp"

namespace {

bool disasm_supported(const w1::arch::arch_spec& spec) {
  auto ctx = w1::asmr::disasm_context::for_arch(spec);
  return ctx.ok();
}

w1::arch::arch_spec parse_arch_or(const char* name, const w1::arch::arch_spec& fallback) {
  w1::arch::arch_spec spec{};
  std::string error;
  if (!w1::arch::parse_arch_spec(name, spec, error)) {
    return fallback;
  }
  return spec;
}

std::vector<uint8_t> nop_bytes_for_arch(const w1::arch::arch_spec& spec) {
  switch (spec.arch_mode) {
    case w1::arch::mode::aarch64:
      return {0x1F, 0x20, 0x03, 0xD5};
    case w1::arch::mode::x86_64:
    case w1::arch::mode::x86_32:
      return {0x90};
    default:
      return {};
  }
}

std::vector<uint8_t> branch_bytes_for_arch(const w1::arch::arch_spec& spec) {
  switch (spec.arch_mode) {
    case w1::arch::mode::aarch64:
      return {0x02, 0x00, 0x00, 0x14}; // b #8
    case w1::arch::mode::x86_64:
    case w1::arch::mode::x86_32:
      return {0xE9, 0x01, 0x00, 0x00, 0x00}; // jmp rel32
    default:
      return {};
  }
}

std::vector<uint8_t> pc_relative_bytes_for_arch(const w1::arch::arch_spec& spec) {
  switch (spec.arch_mode) {
    case w1::arch::mode::aarch64:
      return {0x00, 0x00, 0x00, 0x10}; // adr x0, #0
    case w1::arch::mode::x86_64:
      return {0x8B, 0x05, 0x00, 0x00, 0x00, 0x00}; // mov eax, dword ptr [rip+0]
    default:
      return {};
  }
}

std::vector<uint8_t> arm64_bcond_bytes() {
  return {0x40, 0x00, 0x00, 0x54}; // b.eq #8
}

std::vector<uint8_t> arm64_adrp_bytes() {
  return {0x00, 0x00, 0x00, 0x90}; // adrp x0, #0
}

uint32_t read_u32_le(const uint8_t* bytes) {
  uint32_t value = 0;
  std::memcpy(&value, bytes, sizeof(value));
  return value;
}

uint64_t read_u64_le(const uint8_t* bytes) {
  uint64_t value = 0;
  std::memcpy(&value, bytes, sizeof(value));
  return value;
}

int64_t sign_extend(uint64_t value, unsigned bits) {
  if (bits == 0 || bits >= 64) {
    return static_cast<int64_t>(value);
  }
  const uint64_t mask = 1ULL << (bits - 1);
  return static_cast<int64_t>((value ^ mask) - mask);
}

uint64_t arm64_decode_target(uint32_t inst, uint64_t pc) {
  if ((inst & 0xFC000000u) == 0x14000000u || (inst & 0xFC000000u) == 0x94000000u) {
    const int64_t imm26 = sign_extend(inst & 0x03FFFFFFu, 26) << 2;
    return pc + static_cast<uint64_t>(imm26);
  }
  if ((inst & 0xFF000010u) == 0x54000000u || (inst & 0x7F000000u) == 0x34000000u ||
      (inst & 0x7F000000u) == 0x35000000u) {
    const int64_t imm19 = sign_extend((inst >> 5) & 0x7FFFFu, 19) << 2;
    return pc + static_cast<uint64_t>(imm19);
  }
  if ((inst & 0x7F000000u) == 0x36000000u || (inst & 0x7F000000u) == 0x37000000u) {
    const int64_t imm14 = sign_extend((inst >> 5) & 0x3FFFu, 14) << 2;
    return pc + static_cast<uint64_t>(imm14);
  }
  if ((inst & 0x9F000000u) == 0x10000000u) { // adr
    const uint32_t immlo = (inst >> 29) & 0x3u;
    const uint32_t immhi = (inst >> 5) & 0x7FFFFu;
    const int64_t imm = sign_extend((immhi << 2) | immlo, 21);
    return pc + static_cast<uint64_t>(imm);
  }
  if ((inst & 0x9F000000u) == 0x90000000u) { // adrp
    const uint32_t immlo = (inst >> 29) & 0x3u;
    const uint32_t immhi = (inst >> 5) & 0x7FFFFu;
    const int64_t imm = sign_extend((immhi << 2) | immlo, 21) << 12;
    const uint64_t page = pc & ~0xFFFULL;
    return page + static_cast<uint64_t>(imm);
  }
  return pc;
}

int32_t read_s32_le(const uint8_t* bytes) {
  int32_t value = 0;
  std::memcpy(&value, bytes, sizeof(value));
  return value;
}

std::vector<uint8_t> make_filled_buffer(const std::vector<uint8_t>& code, size_t total_size,
                                        const std::vector<uint8_t>& filler) {
  REQUIRE(!filler.empty());
  std::vector<uint8_t> buffer(total_size, 0);
  size_t offset = 0;
  while (offset + filler.size() <= buffer.size()) {
    std::copy(filler.begin(), filler.end(), buffer.begin() + static_cast<std::ptrdiff_t>(offset));
    offset += filler.size();
  }
  if (!code.empty()) {
    const size_t copy_size = std::min(code.size(), buffer.size());
    std::copy(code.begin(), code.begin() + static_cast<std::ptrdiff_t>(copy_size), buffer.begin());
  }
  return buffer;
}

} // namespace

TEST_CASE("w1h00k relocator copies simple instructions") {
  auto spec = w1::arch::detect_host_arch_spec();
  auto nop = nop_bytes_for_arch(spec);
  if (nop.empty()) {
    CHECK(true);
    return;
  }

  std::vector<uint8_t> code;
  for (int i = 0; i < 4; ++i) {
    code.insert(code.end(), nop.begin(), nop.end());
  }
  auto buffer = make_filled_buffer(code, 64, nop);

  const uint64_t tramp = reinterpret_cast<uint64_t>(buffer.data()) + 0x1000;
  auto result = w1::h00k::reloc::relocate(buffer.data(), 4, tramp);

  CHECK(result.ok());
  CHECK(result.patch_size >= 4);
  CHECK(result.trampoline_bytes.size() == result.patch_size);
  CHECK(std::equal(result.trampoline_bytes.begin(), result.trampoline_bytes.end(), buffer.begin()));
}

TEST_CASE("w1h00k relocator rejects null target") {
  auto result = w1::h00k::reloc::relocate(nullptr, 4);
  CHECK(result.patch_size == 0);
  CHECK(result.error == w1::h00k::reloc::reloc_error::invalid_target);
}

TEST_CASE("w1h00k relocator rejects unsupported arch") {
  auto spec = parse_arch_or("riscv64", w1::arch::detect_host_arch_spec());
  if (!disasm_supported(spec)) {
    CHECK(true);
    return;
  }
  const std::vector<uint8_t> filler = {0x90, 0x90, 0x90, 0x90};
  auto result = w1::h00k::reloc::relocate(filler.data(), 4, 0, spec);
  CHECK(result.patch_size == 0);
  CHECK(result.error == w1::h00k::reloc::reloc_error::unsupported_arch);
}

TEST_CASE("w1h00k relocator requires trampoline address for pc-relative") {
  auto spec = w1::arch::detect_host_arch_spec();
  auto pc_relative = pc_relative_bytes_for_arch(spec);
  if (pc_relative.empty()) {
    CHECK(true);
    return;
  }

  auto filler = nop_bytes_for_arch(spec);
  auto buffer = make_filled_buffer(pc_relative, 64, filler);

  auto result = w1::h00k::reloc::relocate(buffer.data(), pc_relative.size());

  CHECK(result.patch_size == 0);
  CHECK(result.trampoline_bytes.empty());
  CHECK(result.error == w1::h00k::reloc::reloc_error::missing_trampoline);
}

TEST_CASE("w1h00k relocator adjusts x86_64 rel32 branches") {
  auto spec = parse_arch_or("x86_64", w1::arch::detect_host_arch_spec());
  if (spec.arch_mode != w1::arch::mode::x86_64 || !disasm_supported(spec)) {
    CHECK(true);
    return;
  }

  const std::vector<uint8_t> jmp = {0xE9, 0x05, 0x00, 0x00, 0x00};
  const std::vector<uint8_t> filler = {0x90};
  auto buffer = make_filled_buffer(jmp, 64, filler);

  const uint64_t origin = reinterpret_cast<uint64_t>(buffer.data());
  const uint64_t tramp = origin + 0x2000;
  auto result = w1::h00k::reloc::relocate(buffer.data(), jmp.size(), tramp, spec);

  CHECK(result.ok());
  REQUIRE(result.patch_size == jmp.size());
  const int32_t disp = read_s32_le(result.trampoline_bytes.data() + 1);
  const int64_t expected = static_cast<int64_t>(origin + 10) - static_cast<int64_t>(tramp + 5);
  CHECK(disp == expected);
}

TEST_CASE("w1h00k relocator adjusts x86_64 rip-relative memory") {
  auto spec = parse_arch_or("x86_64", w1::arch::detect_host_arch_spec());
  if (spec.arch_mode != w1::arch::mode::x86_64 || !disasm_supported(spec)) {
    CHECK(true);
    return;
  }

  const std::vector<uint8_t> mov = {0x8B, 0x05, 0x00, 0x00, 0x00, 0x00};
  const std::vector<uint8_t> filler = {0x90};
  auto buffer = make_filled_buffer(mov, 64, filler);

  const uint64_t origin = reinterpret_cast<uint64_t>(buffer.data());
  const uint64_t tramp = origin + 0x3000;
  auto result = w1::h00k::reloc::relocate(buffer.data(), mov.size(), tramp, spec);

  CHECK(result.ok());
  REQUIRE(result.patch_size == mov.size());
  const int32_t disp = read_s32_le(result.trampoline_bytes.data() + 2);
  const int64_t expected = static_cast<int64_t>(origin + 6) - static_cast<int64_t>(tramp + 6);
  CHECK(disp == expected);
}

TEST_CASE("w1h00k relocator adjusts x86_32 rel32 branches") {
  auto spec = parse_arch_or("x86", w1::arch::detect_host_arch_spec());
  if (spec.arch_mode != w1::arch::mode::x86_32 || !disasm_supported(spec)) {
    CHECK(true);
    return;
  }

  const std::vector<uint8_t> jmp = {0xE9, 0x05, 0x00, 0x00, 0x00};
  const std::vector<uint8_t> filler = {0x90};
  auto buffer = make_filled_buffer(jmp, 64, filler);

  const uint64_t origin = reinterpret_cast<uint64_t>(buffer.data());
  const uint64_t tramp = origin + 0x1000;
  auto result = w1::h00k::reloc::relocate(buffer.data(), jmp.size(), tramp, spec);

  CHECK(result.ok());
  REQUIRE(result.patch_size == jmp.size());
  const int32_t disp = read_s32_le(result.trampoline_bytes.data() + 1);
  const int64_t expected = static_cast<int64_t>(origin + 10) - static_cast<int64_t>(tramp + 5);
  CHECK(disp == expected);
}

TEST_CASE("w1h00k relocator adjusts arm64 branch targets") {
  auto spec = w1::arch::detect_host_arch_spec();
  if (spec.arch_mode != w1::arch::mode::aarch64) {
    CHECK(true);
    return;
  }

  auto branch = branch_bytes_for_arch(spec);
  auto filler = nop_bytes_for_arch(spec);
  auto buffer = make_filled_buffer(branch, 64, filler);

  const uint64_t target_addr = reinterpret_cast<uint64_t>(buffer.data());
  const uint64_t tramp = target_addr + 0x1000;
  auto result = w1::h00k::reloc::relocate(buffer.data(), branch.size(), tramp);

  CHECK(result.ok());
  REQUIRE(result.patch_size == branch.size());
  const uint32_t relocated = read_u32_le(result.trampoline_bytes.data());
  const uint64_t relocated_target = arm64_decode_target(relocated, tramp);

  CHECK(relocated_target == target_addr + 8);
}

TEST_CASE("w1h00k relocator emits arm64 branch stub when out of range") {
  auto spec = w1::arch::detect_host_arch_spec();
  if (spec.arch_mode != w1::arch::mode::aarch64) {
    CHECK(true);
    return;
  }

  auto branch = branch_bytes_for_arch(spec);
  auto filler = nop_bytes_for_arch(spec);
  auto buffer = make_filled_buffer(branch, 64, filler);

  const uint64_t origin = reinterpret_cast<uint64_t>(buffer.data());
  const uint64_t tramp = origin + 0x20000000ULL; // beyond +/-128MB branch range
  auto result = w1::h00k::reloc::relocate(buffer.data(), branch.size(), tramp);

  CHECK(result.ok());
  REQUIRE(result.patch_size == branch.size());
  REQUIRE(result.trampoline_bytes.size() == 16);

  const uint32_t ldr = read_u32_le(result.trampoline_bytes.data());
  CHECK((ldr & 0xFF000000u) == 0x58000000u);
  CHECK((ldr & 0x1Fu) == 16u);
  CHECK(((ldr >> 5) & 0x7FFFFu) == 2u);

  const uint32_t br = read_u32_le(result.trampoline_bytes.data() + 4);
  CHECK(br == 0xD61F0200u);

  const uint64_t literal = read_u64_le(result.trampoline_bytes.data() + 8);
  CHECK(literal == origin + 8);
}

TEST_CASE("w1h00k relocator adjusts arm64 conditional branches") {
  auto spec = w1::arch::detect_host_arch_spec();
  if (spec.arch_mode != w1::arch::mode::aarch64) {
    CHECK(true);
    return;
  }

  auto bcond = arm64_bcond_bytes();
  auto filler = nop_bytes_for_arch(spec);
  auto buffer = make_filled_buffer(bcond, 64, filler);

  const uint64_t target_addr = reinterpret_cast<uint64_t>(buffer.data());
  const uint64_t tramp = target_addr + 0x1000;
  auto result = w1::h00k::reloc::relocate(buffer.data(), bcond.size(), tramp);

  CHECK(result.ok());
  REQUIRE(result.patch_size == bcond.size());
  const uint32_t relocated = read_u32_le(result.trampoline_bytes.data());
  const uint64_t relocated_target = arm64_decode_target(relocated, tramp);

  CHECK(relocated_target == target_addr + 8);
}

TEST_CASE("w1h00k relocator emits arm64 conditional stub when out of range") {
  auto spec = w1::arch::detect_host_arch_spec();
  if (spec.arch_mode != w1::arch::mode::aarch64) {
    CHECK(true);
    return;
  }

  auto bcond = arm64_bcond_bytes();
  auto filler = nop_bytes_for_arch(spec);
  auto buffer = make_filled_buffer(bcond, 64, filler);

  const uint64_t origin = reinterpret_cast<uint64_t>(buffer.data());
  const uint64_t tramp = origin + 0x20000000ULL;
  auto result = w1::h00k::reloc::relocate(buffer.data(), bcond.size(), tramp);

  CHECK(result.ok());
  REQUIRE(result.patch_size == bcond.size());
  REQUIRE(result.trampoline_bytes.size() == 20);

  const uint32_t skip = read_u32_le(result.trampoline_bytes.data());
  CHECK((skip & 0xFF000010u) == 0x54000000u);
  CHECK((skip & 0xFu) == 0x1u);
  const uint64_t skip_target = arm64_decode_target(skip, tramp);
  CHECK(skip_target == tramp + 16);

  const uint32_t ldr = read_u32_le(result.trampoline_bytes.data() + 4);
  CHECK((ldr & 0xFF000000u) == 0x58000000u);
  CHECK((ldr & 0x1Fu) == 16u);
  CHECK(((ldr >> 5) & 0x7FFFFu) == 2u);

  const uint32_t br = read_u32_le(result.trampoline_bytes.data() + 8);
  CHECK(br == 0xD61F0200u);

  const uint64_t literal = read_u64_le(result.trampoline_bytes.data() + 12);
  CHECK(literal == origin + 8);
}

TEST_CASE("w1h00k relocator adjusts arm64 ADR/ADRP") {
  auto spec = w1::arch::detect_host_arch_spec();
  if (spec.arch_mode != w1::arch::mode::aarch64) {
    CHECK(true);
    return;
  }

  auto adr = pc_relative_bytes_for_arch(spec);
  auto adrp = arm64_adrp_bytes();
  auto filler = nop_bytes_for_arch(spec);

  auto buffer = make_filled_buffer(adr, 64, filler);
  const uint64_t target_addr = reinterpret_cast<uint64_t>(buffer.data());
  const uint64_t tramp = target_addr + 0x1000;
  auto adr_result = w1::h00k::reloc::relocate(buffer.data(), adr.size(), tramp);

  CHECK(adr_result.ok());
  REQUIRE(adr_result.patch_size == adr.size());
  const uint32_t adr_relocated = read_u32_le(adr_result.trampoline_bytes.data());
  const uint64_t adr_target = arm64_decode_target(adr_relocated, tramp);
  CHECK(adr_target == target_addr);

  auto buffer2 = make_filled_buffer(adrp, 64, filler);
  const uint64_t target_addr2 = reinterpret_cast<uint64_t>(buffer2.data());
  const uint64_t tramp2 = target_addr2 + 0x2000;
  auto adrp_result = w1::h00k::reloc::relocate(buffer2.data(), adrp.size(), tramp2);

  CHECK(adrp_result.ok());
  REQUIRE(adrp_result.patch_size == adrp.size());
  const uint32_t adrp_relocated = read_u32_le(adrp_result.trampoline_bytes.data());
  const uint64_t adrp_target = arm64_decode_target(adrp_relocated, tramp2);
  CHECK((adrp_target & ~0xFFFULL) == (target_addr2 & ~0xFFFULL));
}

TEST_CASE("w1h00k relocator emits arm64 ADR stub when out of range") {
  auto spec = w1::arch::detect_host_arch_spec();
  if (spec.arch_mode != w1::arch::mode::aarch64) {
    CHECK(true);
    return;
  }

  auto adr = pc_relative_bytes_for_arch(spec);
  auto filler = nop_bytes_for_arch(spec);
  auto buffer = make_filled_buffer(adr, 64, filler);

  const uint64_t origin = reinterpret_cast<uint64_t>(buffer.data());
  const uint64_t tramp = origin + 0x200000ULL;
  auto result = w1::h00k::reloc::relocate(buffer.data(), adr.size(), tramp);

  CHECK(result.ok());
  REQUIRE(result.patch_size == adr.size());
  REQUIRE(result.trampoline_bytes.size() == 12);

  const uint32_t ldr = read_u32_le(result.trampoline_bytes.data());
  CHECK((ldr & 0xFF000000u) == 0x58000000u);
  CHECK((ldr & 0x1Fu) == 0u);
  CHECK(((ldr >> 5) & 0x7FFFFu) == 1u);

  const uint64_t literal = read_u64_le(result.trampoline_bytes.data() + 4);
  CHECK(literal == origin);
}

TEST_CASE("w1h00k relocator emits arm64 ADRP stub when out of range") {
  auto spec = w1::arch::detect_host_arch_spec();
  if (spec.arch_mode != w1::arch::mode::aarch64) {
    CHECK(true);
    return;
  }

  auto adrp = arm64_adrp_bytes();
  auto filler = nop_bytes_for_arch(spec);
  auto buffer = make_filled_buffer(adrp, 64, filler);

  const uint64_t origin = reinterpret_cast<uint64_t>(buffer.data());
  const uint64_t tramp = origin + 0x200000000ULL;
  auto result = w1::h00k::reloc::relocate(buffer.data(), adrp.size(), tramp);

  CHECK(result.ok());
  REQUIRE(result.patch_size == adrp.size());
  REQUIRE(result.trampoline_bytes.size() == 12);

  const uint32_t ldr = read_u32_le(result.trampoline_bytes.data());
  CHECK((ldr & 0xFF000000u) == 0x58000000u);
  CHECK((ldr & 0x1Fu) == 0u);
  CHECK(((ldr >> 5) & 0x7FFFFu) == 1u);

  const uint64_t literal = read_u64_le(result.trampoline_bytes.data() + 4);
  CHECK(literal == (origin & ~0xFFFULL));
}

TEST_CASE("w1h00k relocator enforces max patch size") {
  auto spec = w1::arch::detect_host_arch_spec();
  auto nop = nop_bytes_for_arch(spec);
  if (nop.empty()) {
    CHECK(true);
    return;
  }

  auto buffer = make_filled_buffer(nop, 128, nop);

  auto result = w1::h00k::reloc::relocate(buffer.data(), 128);

  CHECK(result.patch_size == 0);
  CHECK(result.trampoline_bytes.empty());
  CHECK(result.error == w1::h00k::reloc::reloc_error::invalid_request);
}

TEST_CASE("w1h00k relocator emits x86_64 jmp stub when out of range") {
  auto spec = parse_arch_or("x86_64", w1::arch::detect_host_arch_spec());
  if (spec.arch_mode != w1::arch::mode::x86_64 || !disasm_supported(spec)) {
    CHECK(true);
    return;
  }

  const std::vector<uint8_t> jmp = {0xE9, 0x05, 0x00, 0x00, 0x00};
  const std::vector<uint8_t> filler = {0x90};
  auto buffer = make_filled_buffer(jmp, 64, filler);

  const uint64_t origin = reinterpret_cast<uint64_t>(buffer.data());
  const uint64_t tramp = origin + 0x100000000ULL;
  auto result = w1::h00k::reloc::relocate(buffer.data(), jmp.size(), tramp, spec);

  CHECK(result.ok());
  REQUIRE(result.patch_size == jmp.size());
  REQUIRE(result.trampoline_bytes.size() == 14);

  CHECK(result.trampoline_bytes[0] == 0xFF);
  CHECK(result.trampoline_bytes[1] == 0x25);
  CHECK(result.trampoline_bytes[2] == 0x00);
  CHECK(result.trampoline_bytes[3] == 0x00);
  CHECK(result.trampoline_bytes[4] == 0x00);
  CHECK(result.trampoline_bytes[5] == 0x00);

  const uint64_t literal = read_u64_le(result.trampoline_bytes.data() + 6);
  CHECK(literal == origin + 10);
}

TEST_CASE("w1h00k relocator emits x86_64 jcc stub when out of range") {
  auto spec = parse_arch_or("x86_64", w1::arch::detect_host_arch_spec());
  if (spec.arch_mode != w1::arch::mode::x86_64 || !disasm_supported(spec)) {
    CHECK(true);
    return;
  }

  const std::vector<uint8_t> je = {0x74, 0x02};
  const std::vector<uint8_t> filler = {0x90};
  auto buffer = make_filled_buffer(je, 64, filler);

  const uint64_t origin = reinterpret_cast<uint64_t>(buffer.data());
  const uint64_t tramp = origin + 0x100000000ULL;
  auto result = w1::h00k::reloc::relocate(buffer.data(), je.size(), tramp, spec);

  CHECK(result.ok());
  REQUIRE(result.patch_size == je.size());
  REQUIRE(result.trampoline_bytes.size() == 16);

  CHECK(result.trampoline_bytes[0] == 0x75);
  CHECK(result.trampoline_bytes[1] == 0x0E);
  CHECK(result.trampoline_bytes[2] == 0xFF);
  CHECK(result.trampoline_bytes[3] == 0x25);
  CHECK(result.trampoline_bytes[4] == 0x00);
  CHECK(result.trampoline_bytes[5] == 0x00);
  CHECK(result.trampoline_bytes[6] == 0x00);
  CHECK(result.trampoline_bytes[7] == 0x00);

  const uint64_t literal = read_u64_le(result.trampoline_bytes.data() + 8);
  CHECK(literal == origin + 4);
}
