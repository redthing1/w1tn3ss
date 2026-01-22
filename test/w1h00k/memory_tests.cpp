#include "doctest/doctest.hpp"

#include <cstdint>

#include "w1h00k/memory/memory.hpp"
#include "w1h00k/patcher.hpp"

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
  auto block = w1::h00k::memory::allocate_near(&anchor, 128, 1024 * 1024);
  CHECK(block.ok());
  if (block.ok()) {
    w1::h00k::memory::free_executable(block);
  }
}
