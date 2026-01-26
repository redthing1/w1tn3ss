#include "doctest/doctest.hpp"

#include "w1replay/modules/address_index.hpp"

TEST_CASE("image address index resolves mapping and image") {
  w1::rewind::replay_context context{};

  w1::rewind::image_record image{};
  image.image_id = 2;
  image.name = "image";
  context.images.push_back(image);
  context.images_by_id[2] = 0;

  w1::rewind::mapping_record mapping{};
  mapping.space_id = 0;
  mapping.base = 0x3000;
  mapping.size = 0x1000;
  mapping.image_id = 2;
  mapping.image_offset = 0x200;
  context.mappings.push_back(mapping);
  context.mapping_ranges_by_space[0] = {{mapping.base, mapping.base + mapping.size, &context.mappings[0]}};

  w1replay::image_address_index index(context);
  auto match = index.find(0x3200, 4);
  REQUIRE(match.has_value());
  REQUIRE(match->mapping);
  REQUIRE(match->image);
  CHECK(match->image->image_id == 2);
  CHECK(match->image_offset == 0x400);
}

TEST_CASE("image address index returns null for empty size") {
  w1::rewind::replay_context context{};

  w1replay::image_address_index index(context);
  auto match = index.find(0x4000, 0);
  CHECK(!match.has_value());
}
