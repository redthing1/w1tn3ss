#include "doctest/doctest.hpp"

#include "w1runtime/module_registry.hpp"

namespace {

void module_registry_marker() {}
int module_registry_data_marker = 0;

} // namespace

TEST_CASE("module_registry finds current module") {
  w1::runtime::module_registry registry;
  registry.refresh();

  auto modules = registry.list_modules();
  if (modules.empty()) {
    WARN("module_registry returned no modules; module scanning may be blocked");
    return;
  }

  auto address = reinterpret_cast<uint64_t>(&module_registry_marker);
  auto info = registry.find_containing(address);
  REQUIRE(info != nullptr);
  CHECK(info->full_range.start <= address);
  CHECK(address < info->full_range.end);

  bool in_mapped_range = false;
  for (const auto& range : info->mapped_ranges) {
    if (range.start <= address && address < range.end) {
      in_mapped_range = true;
      break;
    }
  }
  CHECK(in_mapped_range == true);
}

TEST_CASE("module_registry resolves data address to module") {
  w1::runtime::module_registry registry;
  registry.refresh();

  auto modules = registry.list_modules();
  if (modules.empty()) {
    WARN("module_registry returned no modules; module scanning may be blocked");
    return;
  }

  auto address = reinterpret_cast<uint64_t>(&module_registry_data_marker);
  auto info = registry.find_containing(address);
  REQUIRE(info != nullptr);
  CHECK(info->full_range.start <= address);
  CHECK(address < info->full_range.end);
}
