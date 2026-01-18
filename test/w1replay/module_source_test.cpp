#include <filesystem>
#include <fstream>
#include <string>

#include "doctest/doctest.hpp"

#include "w1replay/module_source.hpp"
#include "w1rewind/replay/replay_context.hpp"

TEST_CASE("module_source applies overrides and directory search") {
  namespace fs = std::filesystem;

  w1::rewind::replay_context context;
  w1::rewind::module_record mod1;
  mod1.id = 1;
  mod1.base = 0x1000;
  mod1.size = 0x1000;
  mod1.path = "/old/path/libfoo.so";

  w1::rewind::module_record mod2;
  mod2.id = 2;
  mod2.base = 0x2000;
  mod2.size = 0x2000;
  mod2.path = "bar.dylib";

  context.modules = {mod1, mod2};
  context.modules_by_id[mod1.id] = mod1;
  context.modules_by_id[mod2.id] = mod2;

  fs::path temp_dir = fs::temp_directory_path() / "w1replay_module_source";
  fs::create_directories(temp_dir);
  fs::path bar_path = temp_dir / "bar.dylib";
  {
    std::ofstream out(bar_path.string(), std::ios::binary);
    out << "x";
  }

  w1replay::module_source source;
  source.configure({"libfoo.so=/tmp/libfoo.so"}, {temp_dir.string()});
  source.apply_to_context(context);

  CHECK(context.modules[0].path == "/tmp/libfoo.so");
  CHECK(context.modules[1].path == bar_path.string());
  CHECK(context.modules_by_id[1].path == "/tmp/libfoo.so");
  CHECK(context.modules_by_id[2].path == bar_path.string());

  std::error_code ec;
  fs::remove(bar_path, ec);
  fs::remove(temp_dir, ec);
}
