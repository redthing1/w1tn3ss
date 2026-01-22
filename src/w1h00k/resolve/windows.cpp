#include "w1h00k/resolve/resolve.hpp"

#if defined(_WIN32)
#include <windows.h>
#endif

namespace w1::h00k::resolve {

void* symbol_address(const char* symbol, const char* module) {
#if defined(_WIN32)
  if (!symbol || symbol[0] == '\0') {
    return nullptr;
  }

  HMODULE handle = nullptr;
  if (module && module[0] != '\0') {
    handle = GetModuleHandleA(module);
  } else {
    handle = GetModuleHandleA(nullptr);
  }

  if (!handle) {
    return nullptr;
  }

  return reinterpret_cast<void*>(GetProcAddress(handle, symbol));
#else
  (void)symbol;
  (void)module;
  return nullptr;
#endif
}

} // namespace w1::h00k::resolve
