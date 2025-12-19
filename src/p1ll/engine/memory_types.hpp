#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace p1ll::engine {

enum class memory_protection : int {
  none = 0x00,
  read = 0x01,
  write = 0x02,
  execute = 0x04,
  read_write = read | write,
  read_execute = read | execute,
  read_write_execute = read | write | execute
};

constexpr memory_protection operator|(memory_protection a, memory_protection b) {
  return static_cast<memory_protection>(static_cast<int>(a) | static_cast<int>(b));
}

constexpr memory_protection operator&(memory_protection a, memory_protection b) {
  return static_cast<memory_protection>(static_cast<int>(a) & static_cast<int>(b));
}

constexpr bool has_protection(memory_protection flags, memory_protection check) { return (flags & check) == check; }

struct memory_region {
  uint64_t base_address;
  size_t size;
  memory_protection protection;
  std::string name;
  bool is_executable; // regions that are part of a module's code
  bool is_system;     // regions belonging to system libraries
};

} // namespace p1ll::engine
