#include "doctest/doctest.hpp"

#include "w1h00k/resolve/resolve.hpp"

TEST_CASE("w1h00k resolves known symbol") {
#if defined(_WIN32)
  void* address = w1::h00k::resolve::symbol_address("GetModuleHandleA", "kernel32.dll");
#else
  void* address = w1::h00k::resolve::symbol_address("malloc", nullptr);
#endif
  CHECK(address != nullptr);
}
