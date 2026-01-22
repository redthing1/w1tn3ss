#include "w1h00k/patcher.hpp"

#include <cstdint>
#include <cstring>

#include <windows.h>

namespace w1::h00k {
namespace {

bool protect_region(void* address, size_t size, bool writable) {
  if (!address || size == 0) {
    return false;
  }

  DWORD old_protect = 0;
  DWORD new_protect = writable ? PAGE_READWRITE : PAGE_EXECUTE_READ;
  return VirtualProtect(address, size, new_protect, &old_protect) != 0;
}

void flush_icache(void* address, size_t size) {
  if (!address || size == 0) {
    return;
  }
  FlushInstructionCache(GetCurrentProcess(), address, size);
}

} // namespace

bool code_patcher::write(void* address, const uint8_t* bytes, size_t size) {
  if (!address || !bytes || size == 0) {
    return false;
  }
  if (!protect_region(address, size, true)) {
    return false;
  }
  std::memcpy(address, bytes, size);
  flush_icache(address, size);
  return protect_region(address, size, false);
}

bool code_patcher::restore(void* address, const uint8_t* bytes, size_t size) {
  return write(address, bytes, size);
}

} // namespace w1::h00k
