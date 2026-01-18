#include "w1base/module_identity.hpp"

#include <cstring>

#if defined(_WIN32)
#include <w1base/windows_clean.hpp>
#else
#include <dlfcn.h>
#endif

namespace w1::util {
namespace {

std::string basename_from_path(const std::string& path) {
  if (path.empty()) {
    return path;
  }

  size_t pos = path.find_last_of("/\\");
  if (pos == std::string::npos) {
    return path;
  }

  return path.substr(pos + 1);
}

} // namespace

module_identity module_identity_from_address(const void* address) {
  module_identity result{};
  if (!address) {
    return result;
  }

#if defined(_WIN32)
  HMODULE module = nullptr;
  if (!GetModuleHandleExA(
          GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
          reinterpret_cast<LPCSTR>(address), &module
      )) {
    return result;
  }

  char buffer[MAX_PATH] = {};
  DWORD length = GetModuleFileNameA(module, buffer, MAX_PATH);
  if (length == 0) {
    return result;
  }

  result.path.assign(buffer, length);
  result.name = basename_from_path(result.path);
#else
  Dl_info info;
  std::memset(&info, 0, sizeof(info));
  if (dladdr(address, &info) == 0) {
    return result;
  }

  if (info.dli_fname) {
    result.path = info.dli_fname;
    result.name = basename_from_path(result.path);
  }
#endif

  return result;
}

} // namespace w1::util
