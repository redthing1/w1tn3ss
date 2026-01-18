#include <string>
#include <vector>

#include "doctest/doctest.hpp"

#include "w1rewind/replay/replay_context.hpp"

TEST_CASE("replay_context finds module for address") {
  w1::rewind::replay_context context;

  w1::rewind::module_record mod1;
  mod1.id = 1;
  mod1.base = 0x1000;
  mod1.size = 0x200;
  mod1.path = "mod1";

  w1::rewind::module_record mod2;
  mod2.id = 2;
  mod2.base = 0x2000;
  mod2.size = 0x100;
  mod2.path = "mod2";

  context.modules = {mod1, mod2};

  uint64_t offset = 0;
  auto* found = context.find_module_for_address(0x1000, 1, offset);
  CHECK(found != nullptr);
  CHECK(found->id == 1);
  CHECK(offset == 0);

  offset = 0;
  found = context.find_module_for_address(0x11FF, 1, offset);
  CHECK(found != nullptr);
  CHECK(found->id == 1);
  CHECK(offset == 0x1FF);

  offset = 0;
  found = context.find_module_for_address(0x11FF, 2, offset);
  CHECK(found == nullptr);

  offset = 0;
  found = context.find_module_for_address(0x2000, 0x100, offset);
  CHECK(found != nullptr);
  CHECK(found->id == 2);
  CHECK(offset == 0);

  offset = 0;
  found = context.find_module_for_address(0x3000, 4, offset);
  CHECK(found == nullptr);

  offset = 123;
  found = context.find_module_for_address(0x1000, 0, offset);
  CHECK(found == nullptr);
}
