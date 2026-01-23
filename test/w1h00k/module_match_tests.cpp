#include "doctest/doctest.hpp"

#include <string_view>

#include "w1h00k/resolve/module_match.hpp"

using w1::h00k::resolve::basename_view;
using w1::h00k::resolve::has_path_separator;
using w1::h00k::resolve::module_match_mode;
using w1::h00k::resolve::module_matches;
using w1::h00k::resolve::normalize_match_mode;

TEST_CASE("w1h00k module_match basename_view strips path") {
  CHECK(basename_view("libfoo.so") == std::string_view("libfoo.so"));
  CHECK(basename_view("/usr/lib/libfoo.so") == std::string_view("libfoo.so"));
  CHECK(basename_view("C:\\Windows\\System32\\kernel32.dll") ==
        std::string_view("kernel32.dll"));
}

TEST_CASE("w1h00k module_match detects path separators") {
  CHECK_FALSE(has_path_separator("libfoo.so"));
  CHECK(has_path_separator("/usr/lib/libfoo.so"));
  CHECK(has_path_separator("C:\\Windows\\System32\\kernel32.dll"));
}

TEST_CASE("w1h00k module_match normalizes auto-detect") {
  CHECK(normalize_match_mode("libfoo.so", module_match_mode::auto_detect) ==
        module_match_mode::basename);
  CHECK(normalize_match_mode("/usr/lib/libfoo.so", module_match_mode::auto_detect) ==
        module_match_mode::full_path);
  CHECK(normalize_match_mode("libfoo.so", module_match_mode::full_path) ==
        module_match_mode::full_path);
}

TEST_CASE("w1h00k module_matches honors mode selection") {
  CHECK(module_matches("libfoo.so", "/usr/lib/libfoo.so"));
  CHECK_FALSE(module_matches("libfoo.so", "/usr/lib/libfoo.so", module_match_mode::full_path));
  CHECK(module_matches("/usr/lib/libfoo.so", "/usr/lib/libfoo.so", module_match_mode::full_path));
  CHECK_FALSE(module_matches("/usr/lib/libfoo.so", "/usr/lib/libbar.so", module_match_mode::full_path));
  CHECK(module_matches("/usr/lib/libfoo.so", "/usr/lib/libfoo.so", module_match_mode::basename));
}

TEST_CASE("w1h00k module_matches handles empty request") {
  CHECK(module_matches("", "/usr/lib/libfoo.so"));
  CHECK(module_matches(nullptr, "/usr/lib/libfoo.so"));
  CHECK(module_matches("", ""));
}

TEST_CASE("w1h00k module_matches rejects empty path") {
  CHECK_FALSE(module_matches("libfoo.so", ""));
}

TEST_CASE("w1h00k module_matches casing behavior") {
#if defined(_WIN32)
  CHECK(module_matches("KERNEL32.DLL", "C:\\Windows\\System32\\kernel32.dll"));
  CHECK(module_matches("C:\\WINDOWS\\SYSTEM32\\KERNEL32.DLL",
                       "C:\\Windows\\System32\\kernel32.dll"));
#else
  CHECK_FALSE(module_matches("LIBFOO.SO", "/usr/lib/libfoo.so"));
#endif
}
