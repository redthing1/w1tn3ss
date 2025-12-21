#include "doctest/doctest.hpp"

#include <string>

#include "w1tn3ss/core/instrumentation_policy.hpp"

namespace {

w1::runtime::module_info make_module(
    std::string name, std::string path, bool is_system, uint64_t start = 0x1000, uint64_t end = 0x2000
) {
  w1::runtime::module_info module{};
  module.name = std::move(name);
  module.path = std::move(path);
  module.base_address = start;
  module.size = end - start;
  module.is_system = is_system;
  module.full_range = w1::address_range{start, end};
  module.mapped_ranges = {module.full_range};
  module.exec_ranges = {module.full_range};
  return module;
}

} // namespace

TEST_CASE("instrumentation_policy excludes unnamed modules by default") {
  w1::core::instrumentation_policy policy;
  auto module = make_module("_unnamed_0x1000", "", false);
  CHECK(policy.should_instrument(module) == false);

  policy.include_unnamed_modules = true;
  CHECK(policy.should_instrument(module) == true);
}

TEST_CASE("instrumentation_policy applies default excludes") {
  w1::core::instrumentation_policy policy;
  auto module = make_module("libQBDI", "libQBDI.so", false);
  CHECK(policy.should_instrument(module) == false);

  policy.use_default_excludes = false;
  CHECK(policy.should_instrument(module) == true);
}

TEST_CASE("instrumentation_policy honors include and exclude lists") {
  w1::core::instrumentation_policy policy;
  policy.use_default_excludes = false;
  policy.include_modules = {"target"};
  policy.exclude_modules = {"deny"};

  auto included = make_module("target_mod", "/tmp/target_mod", false);
  auto excluded = make_module("deny_mod", "/tmp/deny_mod", false);
  auto other = make_module("other_mod", "/tmp/other_mod", false);

  CHECK(policy.should_instrument(included) == true);
  CHECK(policy.should_instrument(excluded) == false);
  CHECK(policy.should_instrument(other) == false);
}

TEST_CASE("instrumentation_policy gates system modules") {
  w1::core::instrumentation_policy policy;
  policy.use_default_excludes = false;

  auto system_module = make_module("system_lib", "/usr/lib/system_lib", true);
  auto critical_module = make_module("libSystem.B.dylib", "/usr/lib/libSystem.B.dylib", true);
  CHECK(policy.should_instrument(system_module) == false);

  policy.system_policy = w1::core::system_module_policy::include_critical;
  CHECK(policy.should_instrument(system_module) == false);
  CHECK(policy.should_instrument(critical_module) == true);

  policy.system_policy = w1::core::system_module_policy::include_all;
  CHECK(policy.should_instrument(system_module) == true);
}
