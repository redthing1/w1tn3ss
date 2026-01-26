#include <string>
#include <vector>

#include "doctest/doctest.hpp"

#include "w1rewind/replay/replay_context.hpp"

TEST_CASE("replay_context finds mapping for address") {
  w1::rewind::replay_context context;

  w1::rewind::mapping_record map1{};
  map1.space_id = 0;
  map1.base = 0x1000;
  map1.size = 0x200;
  map1.image_id = 1;
  map1.name = "map1";

  w1::rewind::mapping_record map2{};
  map2.space_id = 0;
  map2.base = 0x2000;
  map2.size = 0x100;
  map2.image_id = 2;
  map2.name = "map2";

  context.mappings = {map1, map2};
  context.mapping_ranges_by_space[0] = {
      {map1.base, map1.base + map1.size, &context.mappings[0]},
      {map2.base, map2.base + map2.size, &context.mappings[1]},
  };

  uint64_t offset = 0;
  auto* found = context.find_mapping_for_address(0, 0x1000, 1, offset);
  CHECK(found != nullptr);
  CHECK(found->image_id == 1);
  CHECK(offset == 0);

  offset = 0;
  found = context.find_mapping_for_address(0, 0x11FF, 1, offset);
  CHECK(found != nullptr);
  CHECK(found->image_id == 1);
  CHECK(offset == 0x1FF);

  offset = 0;
  found = context.find_mapping_for_address(1, 0x11FF, 2, offset);
  CHECK(found == nullptr);

  offset = 0;
  found = context.find_mapping_for_address(0, 0x2000, 0x100, offset);
  CHECK(found != nullptr);
  CHECK(found->image_id == 2);
  CHECK(offset == 0);

  offset = 0;
  found = context.find_mapping_for_address(0, 0x3000, 4, offset);
  CHECK(found == nullptr);

  offset = 123;
  found = context.find_mapping_for_address(0, 0x1000, 0, offset);
  CHECK(found == nullptr);
}
