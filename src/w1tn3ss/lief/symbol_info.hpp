#pragma once

#include <string>

namespace w1::lief {

// cross-platform symbol information structure
struct symbol_info {
  std::string name;
  std::string demangled_name;
  uint64_t offset; // offset within module
  uint64_t size;   // symbol size

  enum type { FUNCTION, OBJECT, UNKNOWN } symbol_type;
  enum binding { LOCAL, GLOBAL, WEAK } symbol_binding;

  std::string version; // symbol version (Linux)
  std::string section; // section name

  bool is_exported;
  bool is_imported;
};

} // namespace w1::lief