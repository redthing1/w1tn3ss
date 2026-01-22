#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "w1h00k/hook.hpp"

namespace w1::h00k::resolve {

struct module_info {
  void* base = nullptr;
  size_t size = 0;
  std::string path{};
};

struct symbol_resolution {
  void* address = nullptr;
  module_info module{};
  hook_error_info error{};
};

struct import_resolution {
  void** slot = nullptr;
  module_info module{};
  hook_error_info error{};
};

std::vector<module_info> enumerate_modules();
symbol_resolution resolve_symbol(const char* symbol, const char* module);
symbol_resolution resolve_symbol(const hook_target& target);
import_resolution resolve_import(const char* symbol, const char* module, const char* import_module);
import_resolution resolve_import(const hook_target& target);

void* symbol_address(const char* symbol, const char* module);

} // namespace w1::h00k::resolve
