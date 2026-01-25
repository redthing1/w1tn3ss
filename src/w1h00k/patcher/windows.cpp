#include "w1h00k/patcher/patcher.hpp"

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

bool query_region_protection(void* address, DWORD& prot_out) {
  MEMORY_BASIC_INFORMATION info{};
  if (!VirtualQuery(address, &info, sizeof(info))) {
    return false;
  }
  prot_out = info.Protect;
  return true;
}

DWORD make_writable_protect(DWORD original) {
  const DWORD flags = original & 0xFFFFFF00u;
  const DWORD base = original & 0xFFu;
  switch (base) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
      return PAGE_EXECUTE_READWRITE | flags;
    default:
      return PAGE_READWRITE | flags;
  }
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

bool data_patcher::write(void* address, const uint8_t* bytes, size_t size) {
  if (!address || !bytes || size == 0) {
    return false;
  }

  DWORD original = 0;
  if (!query_region_protection(address, original)) {
    return false;
  }
  const DWORD writable = make_writable_protect(original);
  DWORD old_protect = 0;
  if (!VirtualProtect(address, size, writable, &old_protect)) {
    return false;
  }

  std::memcpy(address, bytes, size);
  flush_icache(address, size);

  DWORD ignored = 0;
  return VirtualProtect(address, size, original, &ignored) != 0;
}

bool data_patcher::restore(void* address, const uint8_t* bytes, size_t size) {
  return write(address, bytes, size);
}

} // namespace w1::h00k
