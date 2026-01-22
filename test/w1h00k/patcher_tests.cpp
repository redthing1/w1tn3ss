#include "doctest/doctest.hpp"

#include <cstdint>
#include <cstring>

#include "w1h00k/memory/memory.hpp"
#include "w1h00k/patcher.hpp"

TEST_CASE("w1h00k patcher writes and restores bytes") {
  auto block = w1::h00k::memory::allocate_executable(w1::h00k::memory::page_size());
  REQUIRE(block.ok());

  auto* bytes = static_cast<uint8_t*>(block.address);

  w1::h00k::code_patcher patcher;

  const uint8_t initial[4] = {0xAA, 0xAA, 0xAA, 0xAA};
  CHECK(patcher.write(bytes, initial, sizeof(initial)));

  const uint8_t patch[4] = {0x11, 0x22, 0x33, 0x44};
  CHECK(patcher.write(bytes, patch, sizeof(patch)));
  CHECK(std::memcmp(bytes, patch, sizeof(patch)) == 0);

  CHECK(patcher.restore(bytes, initial, sizeof(initial)));
  CHECK(std::memcmp(bytes, initial, sizeof(initial)) == 0);

  w1::h00k::memory::free_executable(block);
}

TEST_CASE("w1h00k patcher rejects invalid inputs") {
  w1::h00k::code_patcher patcher;
  uint8_t data[4] = {0, 1, 2, 3};
  CHECK_FALSE(patcher.write(nullptr, data, sizeof(data)));
  CHECK_FALSE(patcher.write(data, nullptr, sizeof(data)));
  CHECK_FALSE(patcher.write(data, data, 0));
}

TEST_CASE("w1h00k patcher handles zero-sized restore") {
  w1::h00k::code_patcher patcher;
  uint8_t data[1] = {0x90};
  CHECK_FALSE(patcher.restore(data, data, 0));
}
