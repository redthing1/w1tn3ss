#include <filesystem>
#include <fstream>

#include "doctest/doctest.hpp"

#include "w1replay/modules/path_resolver.hpp"
#include "w1rewind/format/trace_format.hpp"

TEST_CASE("image_path_resolver applies overrides and search directories") {
  namespace fs = std::filesystem;

  w1::rewind::image_record image1;
  image1.identity = "/old/path/libfoo.so";

  w1::rewind::image_record image2;
  image2.path = "/recorded/path/bar.dylib";

  fs::path temp_dir = fs::temp_directory_path() / "w1replay_image_resolver";
  fs::create_directories(temp_dir);
  fs::path bar_path = temp_dir / "bar.dylib";
  {
    std::ofstream out(bar_path.string(), std::ios::binary);
    out << "x";
  }

  w1replay::default_image_path_resolver resolver({"libfoo.so=/tmp/libfoo.so"}, {temp_dir.string()});

  auto resolved1 = resolver.resolve_image_path(image1);
  REQUIRE(resolved1.has_value());
  CHECK(*resolved1 == "/tmp/libfoo.so");

  auto resolved2 = resolver.resolve_image_path(image2);
  REQUIRE(resolved2.has_value());
  CHECK(*resolved2 == bar_path.string());

  auto region1 = resolver.resolve_region_name("/old/path/libfoo.so");
  REQUIRE(region1.has_value());
  CHECK(*region1 == "/tmp/libfoo.so");

  auto region2 = resolver.resolve_region_name("bar.dylib");
  CHECK(!region2.has_value());

  std::error_code ec;
  fs::remove(bar_path, ec);
  fs::remove(temp_dir, ec);
}

TEST_CASE("image_path_resolver does not resolve without explicit mappings or dirs") {
  w1::rewind::image_record image{};
  image.identity = "/recorded/path/libexample.so";
  image.path = "/recorded/path/libexample.so";

  w1replay::default_image_path_resolver resolver({}, {});
  auto resolved = resolver.resolve_image_path(image);
  CHECK(!resolved.has_value());
}

TEST_CASE("image_path_resolver disambiguates basename collisions with exact matches") {
  w1::rewind::image_record exact_image{};
  exact_image.path = "/opt/a/libshared.so";

  w1::rewind::image_record ambiguous_image{};
  ambiguous_image.path = "/opt/other/libshared.so";

  w1replay::default_image_path_resolver resolver(
      {"/opt/a/libshared.so=/tmp/libshared_a.so", "/opt/b/libshared.so=/tmp/libshared_b.so"}, {}
  );

  auto exact = resolver.resolve_image_path(exact_image);
  REQUIRE(exact.has_value());
  CHECK(*exact == "/tmp/libshared_a.so");

  auto ambiguous = resolver.resolve_image_path(ambiguous_image);
  CHECK(!ambiguous.has_value());

  auto region = resolver.resolve_region_name("libshared.so");
  CHECK(!region.has_value());
}
