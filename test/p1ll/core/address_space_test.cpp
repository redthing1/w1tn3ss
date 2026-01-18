#include "doctest/doctest.hpp"

#include "p1ll/engine/address_space.hpp"
#include "p1ll/engine/types.hpp"
#include "test_helpers.hpp"

#include <array>
#include <span>

namespace {

using p1ll::engine::buffer_address_space;
using p1ll::engine::error_code;
using p1ll::engine::process_address_space;
using p1ll::test_helpers::make_buffer;

} // namespace

TEST_CASE("buffer address space reads and writes") {
  auto buffer = make_buffer(8, 0x11);
  buffer_address_space space(std::span<uint8_t>(buffer.data(), buffer.size()));

  auto read = space.read(0, 4);
  REQUIRE(read.ok());
  CHECK(read.value.size() == 4);
  CHECK(read.value[0] == 0x11);

  std::array<uint8_t, 2> bytes = {0x22, 0x33};
  auto write_status = space.write(2, bytes);
  CHECK(write_status.ok());
  CHECK(buffer[2] == 0x22);
  CHECK(buffer[3] == 0x33);
}

TEST_CASE("buffer address space rejects out-of-bounds") {
  auto buffer = make_buffer(4, 0x00);
  buffer_address_space space(std::span<uint8_t>(buffer.data(), buffer.size()));

  auto read = space.read(4, 1);
  CHECK_FALSE(read.ok());
  CHECK(read.status_info.code == error_code::invalid_argument);

  std::array<uint8_t, 1> bytes = {0xaa};
  auto write_status = space.write(4, bytes);
  CHECK_FALSE(write_status.ok());
  CHECK(write_status.code == error_code::invalid_argument);
}

TEST_CASE("buffer address space region info handles missing") {
  auto buffer = make_buffer(4, 0x00);
  buffer_address_space space(std::span<uint8_t>(buffer.data(), buffer.size()));

  auto region = space.region_info(4);
  CHECK_FALSE(region.ok());
  CHECK(region.status_info.code == error_code::not_found);
}

TEST_CASE("buffer address space allocation is unsupported") {
  auto buffer = make_buffer(4, 0x00);
  buffer_address_space space(std::span<uint8_t>(buffer.data(), buffer.size()));

  auto alloc = space.allocate(16, p1ll::engine::memory_protection::read_write);
  CHECK_FALSE(alloc.ok());
  CHECK(alloc.status_info.code == error_code::unsupported);
}

TEST_CASE("process address space exposes page size") {
  process_address_space space;
  auto page = space.page_size();
  CHECK(page.ok());
  CHECK(page.value > 0);
}

TEST_CASE("process address space region enumeration is best-effort") {
  process_address_space space;
  auto regions = space.regions({});
  if (!regions.ok()) {
    INFO("region enumeration unavailable: " << regions.status_info.message);
    return;
  }
  CHECK_FALSE(regions.value.empty());
}
