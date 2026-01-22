#include "w1h00k/resolve/resolve.hpp"

#include <dlfcn.h>

namespace w1::h00k::resolve {
namespace {

void* open_module_handle(const char* module) {
  if (!module || module[0] == '\0') {
    return nullptr;
  }
  void* handle = dlopen(module, RTLD_LAZY | RTLD_NOLOAD);
  return handle;
}

} // namespace

void* symbol_address(const char* symbol, const char* module) {
  if (!symbol || symbol[0] == '\0') {
    return nullptr;
  }

  if (!module || module[0] == '\0') {
    return dlsym(RTLD_DEFAULT, symbol);
  }

  void* handle = open_module_handle(module);
  if (!handle) {
    return nullptr;
  }

  void* address = dlsym(handle, symbol);
  dlclose(handle);
  return address;
}

} // namespace w1::h00k::resolve
