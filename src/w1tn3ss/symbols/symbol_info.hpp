#pragma once

#include <string>
#include <cstdint>

namespace w1::symbols {

// cross-platform symbol information structure
struct symbol_info {
  std::string name;
  std::string demangled_name;
  uint64_t offset; // offset within module
  uint64_t size;   // symbol size

  enum type { FUNCTION, OBJECT, DEBUG, UNKNOWN } symbol_type = UNKNOWN;
  enum binding { LOCAL, GLOBAL, WEAK, UNKNOWN_BINDING } symbol_binding = UNKNOWN_BINDING;

  std::string version; // symbol version (Linux)
  std::string section; // section name

  bool is_exported;
  bool is_imported;
};

} // namespace w1::symbols