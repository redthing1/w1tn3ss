#include <string>
#include <vector>

#include "doctest/doctest.hpp"

#include "w1replay/gdb/memory_map.hpp"
#include "w1replay/modules/path_resolver.hpp"
#include "w1rewind/replay/replay_context.hpp"

namespace {

struct stub_resolver final : public w1replay::image_path_resolver {
  std::optional<std::string> resolve_image_path(const w1::rewind::image_record&) const override { return std::nullopt; }
  std::optional<std::string> resolve_region_name(std::string_view name) const override {
    if (name == "mod") {
      return "resolved-mod";
    }
    return std::nullopt;
  }
};

} // namespace

TEST_CASE("gdb memory map skips recorded bytes inside mapping ranges") {
  w1::rewind::replay_context context{};

  w1::rewind::image_record image{};
  image.image_id = 1;
  image.name = "mod";
  context.images.push_back(image);
  context.images_by_id[1] = 0;

  w1::rewind::mapping_record mapping{};
  mapping.space_id = 0;
  mapping.base = 0x1000;
  mapping.size = 0x100;
  mapping.perms = w1::rewind::mapping_perm::read | w1::rewind::mapping_perm::exec;
  mapping.image_id = 1;
  mapping.name = "mod";
  context.mappings.push_back(mapping);

  w1::rewind::replay_state state;
  std::vector<uint8_t> inside{0xAA};
  std::vector<uint8_t> outside{0xBB, 0xCC};
  state.apply_memory_bytes(0, 0x1010, inside);
  state.apply_memory_bytes(0, 0x3000, outside);

  auto regions = w1replay::gdb::build_memory_map(context, &state, nullptr, nullptr);

  bool saw_mapping = false;
  bool saw_recorded = false;
  for (const auto& region : regions) {
    if (region.start == 0x1000 && region.size == 0x100) {
      saw_mapping = true;
    }
    if (region.name == "rewind.recorded") {
      saw_recorded = true;
      CHECK(region.start == 0x3000);
      CHECK(region.size == 2);
    }
  }

  CHECK(saw_mapping);
  CHECK(saw_recorded);
}

TEST_CASE("gdb memory map resolves mapping names with resolver") {
  w1::rewind::replay_context context{};

  w1::rewind::image_record image{};
  image.image_id = 1;
  image.name = "fallback";
  context.images.push_back(image);
  context.images_by_id[1] = 0;

  w1::rewind::mapping_record mapping{};
  mapping.space_id = 0;
  mapping.base = 0x2000;
  mapping.size = 0x80;
  mapping.perms = w1::rewind::mapping_perm::read;
  mapping.image_id = 1;
  mapping.name = "mod";
  context.mappings.push_back(mapping);

  w1::rewind::replay_state state;
  std::vector<uint8_t> outside{0xDD};
  state.apply_memory_bytes(0, 0x4000, outside);

  stub_resolver resolver;
  auto regions = w1replay::gdb::build_memory_map(context, &state, nullptr, &resolver);

  bool saw_mapping = false;
  bool saw_recorded = false;
  for (const auto& entry : regions) {
    if (entry.start == 0x2000 && entry.size == 0x80) {
      saw_mapping = true;
      CHECK(entry.name == "resolved-mod");
    }
    if (entry.name == "rewind.recorded") {
      saw_recorded = true;
      CHECK(entry.start == 0x4000);
      CHECK(entry.size == 1);
    }
  }

  CHECK(saw_mapping);
  CHECK(saw_recorded);
}

TEST_CASE("gdb memory map uses resolved mapping ranges when present") {
  w1::rewind::replay_context context{};

  w1::rewind::mapping_record mapping_a{};
  mapping_a.space_id = 0;
  mapping_a.base = 0x1000;
  mapping_a.size = 0x200;
  mapping_a.perms = w1::rewind::mapping_perm::read;
  mapping_a.name = "mapA";

  w1::rewind::mapping_record mapping_b{};
  mapping_b.space_id = 0;
  mapping_b.base = 0x1100;
  mapping_b.size = 0x100;
  mapping_b.perms = w1::rewind::mapping_perm::read | w1::rewind::mapping_perm::exec;
  mapping_b.name = "mapB";

  context.mappings = {mapping_a, mapping_b};
  context.mapping_ranges_by_space[0] = {
      {0x1000, 0x1100, &context.mappings[0]},
      {0x1100, 0x1200, &context.mappings[1]},
  };

  auto regions = w1replay::gdb::build_memory_map(context, nullptr, nullptr, nullptr);
  size_t mapping_regions = 0;
  bool saw_a = false;
  bool saw_b = false;
  for (const auto& region : regions) {
    if (region.start == 0x1000) {
      mapping_regions++;
      saw_a = true;
      CHECK(region.size == 0x100);
    } else if (region.start == 0x1100) {
      mapping_regions++;
      saw_b = true;
      CHECK(region.size == 0x100);
    }
    CHECK(region.size != 0x200);
  }
  CHECK(mapping_regions == 2);
  CHECK(saw_a);
  CHECK(saw_b);
}

TEST_CASE("gdb memory map prefers mapping_state over static context") {
  w1::rewind::replay_context context{};

  w1::rewind::mapping_record mapping{};
  mapping.space_id = 0;
  mapping.base = 0x1000;
  mapping.size = 0x100;
  mapping.perms = w1::rewind::mapping_perm::read;
  mapping.name = "map";
  context.mappings.push_back(mapping);

  w1::rewind::mapping_state mapping_state;
  std::string mapping_error;
  REQUIRE(mapping_state.reset(context.mappings, mapping_error));

  w1::rewind::mapping_record unmap{};
  unmap.kind = w1::rewind::mapping_event_kind::unmap;
  unmap.space_id = 0;
  unmap.base = 0x1000;
  unmap.size = 0x100;
  std::string error;
  REQUIRE(mapping_state.apply_event(unmap, error));

  w1::rewind::replay_state state;
  std::vector<uint8_t> bytes{0xAB};
  state.apply_memory_bytes(0, 0x1000, bytes);

  auto regions = w1replay::gdb::build_memory_map(context, &state, &mapping_state, nullptr);
  bool saw_mapping = false;
  bool saw_recorded = false;
  for (const auto& region : regions) {
    if (region.start == 0x1000 && region.size == 0x100) {
      saw_mapping = true;
    }
    if (region.name == "rewind.recorded") {
      saw_recorded = true;
      CHECK(region.start == 0x1000);
      CHECK(region.size == 1);
    }
  }
  CHECK(!saw_mapping);
  CHECK(saw_recorded);
}
