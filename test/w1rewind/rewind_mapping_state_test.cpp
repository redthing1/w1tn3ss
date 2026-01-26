#include <string>
#include <vector>

#include "doctest/doctest.hpp"

#include "w1rewind/replay/mapping_state.hpp"

TEST_CASE("mapping_state applies map/unmap/protect events without remapping gaps") {
  w1::rewind::mapping_state state;
  w1::rewind::mapping_record map{};
  map.kind = w1::rewind::mapping_event_kind::map;
  map.space_id = 0;
  map.base = 0x1000;
  map.size = 0x100;
  map.perms = w1::rewind::mapping_perm::read;
  map.image_id = 1;
  map.image_offset = 0;

  std::vector<w1::rewind::mapping_record> initial{map};
  std::string error;
  REQUIRE(state.reset(initial, error));

  uint64_t offset = 0;
  auto mapping = state.find_mapping_for_address(0, 0x1008, 1, offset);
  REQUIRE(mapping != nullptr);
  CHECK(mapping->image_id == 1);
  CHECK(offset == 0x8);

  w1::rewind::mapping_record unmap{};
  unmap.kind = w1::rewind::mapping_event_kind::unmap;
  unmap.space_id = 0;
  unmap.base = 0x1080;
  unmap.size = 0x20;

  REQUIRE(state.apply_event(unmap, error));

  offset = 0;
  CHECK(state.find_mapping_for_address(0, 0x1090, 1, offset) == nullptr);
  mapping = state.find_mapping_for_address(0, 0x1010, 1, offset);
  REQUIRE(mapping != nullptr);

  w1::rewind::mapping_record protect{};
  protect.kind = w1::rewind::mapping_event_kind::protect;
  protect.space_id = 0;
  protect.base = 0x1000;
  protect.size = 0x100;
  protect.perms = w1::rewind::mapping_perm::read | w1::rewind::mapping_perm::exec;

  REQUIRE(state.apply_event(protect, error));

  offset = 0;
  CHECK(state.find_mapping_for_address(0, 0x1090, 1, offset) == nullptr);
  mapping = state.find_mapping_for_address(0, 0x1010, 1, offset);
  REQUIRE(mapping != nullptr);
  CHECK((mapping->perms & w1::rewind::mapping_perm::exec) != w1::rewind::mapping_perm::none);
}

TEST_CASE("mapping_state snapshot adjusts image offsets for trimmed ranges") {
  w1::rewind::mapping_state state;
  w1::rewind::mapping_record map{};
  map.kind = w1::rewind::mapping_event_kind::map;
  map.space_id = 0;
  map.base = 0x1000;
  map.size = 0x100;
  map.perms = w1::rewind::mapping_perm::read;
  map.image_id = 1;
  map.image_offset = 0;

  std::vector<w1::rewind::mapping_record> initial{map};
  std::string error;
  REQUIRE(state.reset(initial, error));

  w1::rewind::mapping_record unmap{};
  unmap.kind = w1::rewind::mapping_event_kind::unmap;
  unmap.space_id = 0;
  unmap.base = 0x1000;
  unmap.size = 0x20;

  REQUIRE(state.apply_event(unmap, error));

  std::vector<w1::rewind::mapping_record> snapshot;
  REQUIRE(state.snapshot(snapshot, error));
  REQUIRE(snapshot.size() == 1);
  CHECK(snapshot[0].base == 0x1020);
  CHECK(snapshot[0].size == 0xE0);
  CHECK(snapshot[0].image_offset == 0x20);
  CHECK(snapshot[0].kind == w1::rewind::mapping_event_kind::map);
}
