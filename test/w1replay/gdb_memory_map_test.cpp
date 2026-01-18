#include <vector>

#include "doctest/doctest.hpp"

#include "w1replay/gdb/memory_map.hpp"

TEST_CASE("gdb memory map skips recorded bytes inside module ranges") {
  w1::rewind::module_record module{};
  module.id = 1;
  module.base = 0x1000;
  module.size = 0x100;
  module.permissions = w1::rewind::module_perm::read | w1::rewind::module_perm::exec;
  module.path = "mod";

  w1::rewind::replay_state state;
  state.apply_memory_bytes(0x1010, {0xAA});
  state.apply_memory_bytes(0x3000, {0xBB, 0xCC});

  auto regions = w1replay::gdb::build_memory_map({module}, {}, &state);

  bool saw_module = false;
  bool saw_recorded = false;
  for (const auto& region : regions) {
    if (region.start == 0x1000 && region.size == 0x100) {
      saw_module = true;
    }
    if (region.name == "rewind.recorded") {
      saw_recorded = true;
      CHECK(region.start == 0x3000);
      CHECK(region.size == 2);
    }
  }

  CHECK(saw_module);
  CHECK(saw_recorded);
}
