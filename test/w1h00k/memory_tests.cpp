#include "doctest/doctest.hpp"

#include <cstdint>

#include "w1h00k/memory/memory.hpp"
#include "w1h00k/patcher/patcher.hpp"

TEST_CASE("w1h00k executable allocation basics") {
  const size_t request_size = 64;
  auto block = w1::h00k::memory::allocate_executable(request_size);
  REQUIRE(block.ok());
  CHECK(block.size >= request_size);

  auto* bytes = static_cast<uint8_t*>(block.address);
  w1::h00k::code_patcher patcher;
  const uint8_t payload[4] = {0x5A, 0x5A, 0x5A, 0x5A};
  CHECK(patcher.write(bytes, payload, sizeof(payload)));
  CHECK(bytes[0] == 0x5A);

  w1::h00k::memory::free_executable(block);
}

TEST_CASE("w1h00k executable allocation rejects zero size") {
  auto block = w1::h00k::memory::allocate_executable(0);
  CHECK_FALSE(block.ok());
  CHECK(block.address == nullptr);
  CHECK(block.size == 0);
}

TEST_CASE("w1h00k near allocation returns memory") {
  uint8_t anchor = 0;
  constexpr size_t range = 256 * 1024 * 1024;
  auto block = w1::h00k::memory::allocate_near(&anchor, 128, range);
  if (!block.ok()) {
    WARN("allocate_near failed; no suitable region found within range");
    return;
  }

  const uintptr_t anchor_addr = reinterpret_cast<uintptr_t>(&anchor);
  const uintptr_t block_addr = reinterpret_cast<uintptr_t>(block.address);
  const uintptr_t distance = block_addr >= anchor_addr ? block_addr - anchor_addr : anchor_addr - block_addr;
  CHECK(distance <= range);

  w1::h00k::memory::free_executable(block);
}

TEST_CASE("w1h00k near allocation validates inputs") {
  uint8_t anchor = 0;
  CHECK_FALSE(w1::h00k::memory::allocate_near(nullptr, 16, 1024).ok());
  CHECK_FALSE(w1::h00k::memory::allocate_near(&anchor, 0, 1024).ok());
  CHECK_FALSE(w1::h00k::memory::allocate_near(&anchor, 16, 0).ok());
}

TEST_CASE("w1h00k near allocation rejects too-small range") {
  uint8_t anchor = 0;
  auto block = w1::h00k::memory::allocate_near(&anchor, 4096, 1);
  CHECK_FALSE(block.ok());
}
