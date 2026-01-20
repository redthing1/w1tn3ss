#include "doctest/doctest.hpp"

#include "w1rewind/record/memory_map_utils.hpp"

TEST_CASE("assign_memory_map_image_ids matches regions to modules") {
  w1::rewind::module_record mod1{};
  mod1.id = 1;
  mod1.base = 0x1000;
  mod1.size = 0x100;

  w1::rewind::module_record mod2{};
  mod2.id = 2;
  mod2.base = 0x2000;
  mod2.size = 0x80;

  std::vector<w1::rewind::module_record> modules{mod1, mod2};

  w1::rewind::memory_region_record region1{};
  region1.base = 0x1000;
  region1.size = 0x10;

  w1::rewind::memory_region_record region2{};
  region2.base = 0x2050;
  region2.size = 0x10;

  w1::rewind::memory_region_record region3{};
  region3.base = 0x3000;
  region3.size = 0x10;

  w1::rewind::memory_region_record region4{};
  region4.base = 0x1008;
  region4.size = 0x8;
  region4.image_id = 99;

  std::vector<w1::rewind::memory_region_record> regions{region1, region2, region3, region4};

  w1::rewind::assign_memory_map_image_ids(regions, modules);

  CHECK(regions[0].image_id == 1);
  CHECK(regions[1].image_id == 2);
  CHECK(regions[2].image_id == 0);
  CHECK(regions[3].image_id == 99);
}
