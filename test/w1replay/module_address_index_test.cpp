#include "doctest/doctest.hpp"

#include "w1replay/modules/address_index.hpp"

TEST_CASE("module address index prefers memory map image ids") {
  w1::rewind::replay_context context{};

  w1::rewind::module_record module_a{};
  module_a.id = 1;
  module_a.base = 0x1000;
  module_a.size = 0x1000;

  w1::rewind::module_record module_b{};
  module_b.id = 2;
  module_b.base = 0x3000;
  module_b.size = 0x1000;

  context.modules = {module_a, module_b};

  w1::rewind::memory_region_record region{};
  region.base = 0x3200;
  region.size = 0x100;
  region.image_id = 2;
  context.memory_map = {region};

  w1replay::module_address_index index(context);
  auto match = index.find(0x3200, 4);
  REQUIRE(match.has_value());
  REQUIRE(match->module);
  CHECK(match->module->id == 2);
  CHECK(match->module_offset == 0x200);
}

TEST_CASE("module address index falls back to module ranges") {
  w1::rewind::replay_context context{};

  w1::rewind::module_record module{};
  module.id = 5;
  module.base = 0x4000;
  module.size = 0x200;

  context.modules = {module};

  w1replay::module_address_index index(context);
  auto match = index.find(0x4010, 8);
  REQUIRE(match.has_value());
  REQUIRE(match->module);
  CHECK(match->module->id == 5);
  CHECK(match->module_offset == 0x10);
}
