#include <filesystem>
#include <fstream>

#include "doctest/doctest.hpp"

#include "w1replay/modules/path_resolver.hpp"
#include "w1rewind/format/trace_format.hpp"

TEST_CASE("module_path_resolver applies overrides and search directories") {
  namespace fs = std::filesystem;

  w1::rewind::module_record mod1;
  mod1.path = "/old/path/libfoo.so";

  w1::rewind::module_record mod2;
  mod2.path = "bar.dylib";

  fs::path temp_dir = fs::temp_directory_path() / "w1replay_module_resolver";
  fs::create_directories(temp_dir);
  fs::path bar_path = temp_dir / "bar.dylib";
  {
    std::ofstream out(bar_path.string(), std::ios::binary);
    out << "x";
  }

  w1replay::default_module_path_resolver resolver({"libfoo.so=/tmp/libfoo.so"}, {temp_dir.string()});

  auto resolved1 = resolver.resolve_module_path(mod1);
  REQUIRE(resolved1.has_value());
  CHECK(*resolved1 == "/tmp/libfoo.so");

  auto resolved2 = resolver.resolve_module_path(mod2);
  REQUIRE(resolved2.has_value());
  CHECK(*resolved2 == bar_path.string());

  auto region1 = resolver.resolve_region_name("/old/path/libfoo.so");
  REQUIRE(region1.has_value());
  CHECK(*region1 == "/tmp/libfoo.so");

  auto region2 = resolver.resolve_region_name("bar.dylib");
  REQUIRE(region2.has_value());
  CHECK(*region2 == bar_path.string());

  std::error_code ec;
  fs::remove(bar_path, ec);
  fs::remove(temp_dir, ec);
}
