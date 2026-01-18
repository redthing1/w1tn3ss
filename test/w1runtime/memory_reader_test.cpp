#include "doctest/doctest.hpp"

#include <array>
#include <cstdint>

#include "w1runtime/module_registry.hpp"
#include "w1runtime/memory_reader.hpp"

TEST_CASE("memory_reader reads bytes") {
  std::array<uint8_t, 4> buffer = {1, 2, 3, 4};
  w1::runtime::module_registry modules;
  w1::util::memory_reader reader(nullptr, modules);

  auto result = reader.read_bytes(reinterpret_cast<uint64_t>(buffer.data()), buffer.size());
  REQUIRE(result.has_value());
  CHECK(result->size() == buffer.size());
  CHECK((*result)[0] == 1);
  CHECK((*result)[3] == 4);
}

TEST_CASE("memory_reader reads string") {
  const char message[] = "hello";
  w1::runtime::module_registry modules;
  w1::util::memory_reader reader(nullptr, modules);

  auto result = reader.read_string(reinterpret_cast<uint64_t>(message), 16);
  REQUIRE(result.has_value());
  CHECK(*result == "hello");
}

TEST_CASE("memory_reader rejects null address") {
  w1::runtime::module_registry modules;
  w1::util::memory_reader reader(nullptr, modules);

  auto bytes = reader.read_bytes(0, 4);
  CHECK(bytes.has_value() == false);

  auto text = reader.read_string(0, 4);
  CHECK(text.has_value() == false);
}
