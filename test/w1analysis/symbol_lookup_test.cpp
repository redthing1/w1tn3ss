#include "doctest/doctest.hpp"

#include "w1analysis/symbol_lookup.hpp"
#include "w1runtime/module_catalog.hpp"

namespace {

int symbol_lookup_target(int value) { return value + 1; }

} // namespace

TEST_CASE("symbol_lookup resolves current symbol") {
  w1::runtime::module_catalog registry;
  registry.refresh();

  auto modules = registry.list_modules();
  if (modules.empty()) {
    WARN("module_catalog returned no modules; module scanning may be blocked");
    return;
  }

  w1::analysis::symbol_lookup lookup(&registry);
  uint64_t address = reinterpret_cast<uint64_t>(&symbol_lookup_target);

  auto module = registry.find_containing(address);
  REQUIRE(module != nullptr);

  auto info = lookup.resolve(address);
  REQUIRE(info.has_value());
  CHECK(info->address == address);
  CHECK(info->module_name.empty() == false);
  CHECK(info->module_offset == address - module->base_address);
  CHECK(info->module_offset < module->size);

  if (!info->has_symbol) {
    WARN("symbol_lookup did not resolve a symbol name for the target function");
  } else {
    CHECK(info->symbol_name.empty() == false);
  }

  CHECK(lookup.cache_size() > 0);
}
