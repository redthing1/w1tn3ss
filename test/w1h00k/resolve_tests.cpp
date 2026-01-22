#include "doctest/doctest.hpp"

#include <cstdlib>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "w1h00k/resolve/resolve.hpp"

namespace {

void touch_imports() {
#if defined(_WIN32)
  (void)GetModuleHandleA(nullptr);
#else
  void* ptr = std::malloc(32);
  std::free(ptr);
#endif
}

} // namespace

TEST_CASE("w1h00k resolves known symbol") {
#if defined(_WIN32)
  auto result = w1::h00k::resolve::resolve_symbol("GetModuleHandleA", "kernel32.dll");
#else
  auto result = w1::h00k::resolve::resolve_symbol("malloc", nullptr);
#endif
  CHECK(result.error.ok());
  CHECK(result.address != nullptr);
}

TEST_CASE("w1h00k enumerates modules") {
  auto modules = w1::h00k::resolve::enumerate_modules();
  CHECK(!modules.empty());
}

TEST_CASE("w1h00k resolves import slot in current module") {
  touch_imports();
#if defined(_WIN32)
  auto result = w1::h00k::resolve::resolve_import("GetModuleHandleA", nullptr, "kernel32.dll");
#else
  auto result = w1::h00k::resolve::resolve_import("malloc", nullptr, nullptr);
#endif
  CHECK(result.error.ok());
  CHECK(result.slot != nullptr);
  if (result.slot) {
    CHECK(*result.slot != nullptr);
  }
}
