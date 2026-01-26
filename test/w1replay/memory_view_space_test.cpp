#include <array>
#include <cstddef>
#include <vector>

#include "doctest/doctest.hpp"

#include "w1replay/memory/memory_view.hpp"
#include "w1replay/modules/image_bytes.hpp"
#include "w1replay/modules/image_reader.hpp"
#include "w1rewind/replay/replay_context.hpp"
#include "w1rewind/replay/replay_state.hpp"

namespace {

struct null_image_reader final : w1replay::image_reader {
  w1replay::image_read_result read_image_bytes(
      const w1::rewind::image_record&, uint64_t, size_t size
  ) override {
    return w1replay::make_empty_image_read(size);
  }

  w1replay::image_read_result read_address_bytes(
      const w1::rewind::replay_context&, uint64_t, size_t size, uint32_t
  ) override {
    return w1replay::make_empty_image_read(size);
  }

  const w1replay::image_layout* layout_for_image(const w1::rewind::image_record&, std::string& error) override {
    error = "unavailable";
    return nullptr;
  }
};

} // namespace

TEST_CASE("replay memory view reads per-space memory") {
  w1::rewind::replay_context context{};
  w1::rewind::replay_state state;

  std::vector<uint8_t> bytes_space0 = {0x11};
  std::vector<uint8_t> bytes_space1 = {0xAA, 0xBB};
  state.apply_memory_bytes(0, 0x1000, bytes_space0);
  state.apply_memory_bytes(1, 0x1000, bytes_space1);

  null_image_reader reader;
  w1replay::replay_memory_view view(&context, &state, &reader);

  auto bytes0 = view.read(0, 0x1000, 2);
  REQUIRE(bytes0.bytes.size() == 2);
  REQUIRE(bytes0.known.size() == 2);
  CHECK(bytes0.known[0] == 1);
  CHECK(bytes0.known[1] == 0);
  CHECK(bytes0.bytes[0] == std::byte{0x11});

  auto bytes1 = view.read(1, 0x1000, 2);
  REQUIRE(bytes1.bytes.size() == 2);
  REQUIRE(bytes1.known.size() == 2);
  CHECK(bytes1.known[0] == 1);
  CHECK(bytes1.known[1] == 1);
  CHECK(bytes1.bytes[0] == std::byte{0xAA});
  CHECK(bytes1.bytes[1] == std::byte{0xBB});
}
