#include "w1h00k/resolve/resolve.hpp"

#include <algorithm>
#include <cctype>
#include <string_view>

#if defined(_WIN32)
#include <tlhelp32.h>
#include <windows.h>
#endif

namespace w1::h00k::resolve {
namespace {

hook_error_info make_error(hook_error code, const char* detail) {
  hook_error_info info{};
  info.code = code;
  info.detail = detail;
  return info;
}

std::string to_lower(std::string_view value) {
  std::string out(value.begin(), value.end());
  for (auto& ch : out) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }
  return out;
}

std::string_view basename_view(std::string_view path) {
  const size_t pos = path.find_last_of("/\\");
  if (pos == std::string_view::npos) {
    return path;
  }
  return path.substr(pos + 1);
}

bool module_matches(const char* requested, const std::string& path) {
  if (!requested || requested[0] == '\0') {
    return true;
  }
  if (path.empty()) {
    return false;
  }
  const std::string req = to_lower(requested);
  const std::string full = to_lower(path);
  const bool has_sep = req.find('/') != std::string::npos || req.find('\\') != std::string::npos;
  if (has_sep) {
    return full == req;
  }
  return to_lower(std::string(basename_view(full))) == req;
}

#if defined(_WIN32)
bool module_info_from_entry(const MODULEENTRY32& entry, module_info& out) {
  out.base = entry.modBaseAddr;
  out.size = entry.modBaseSize;
  out.path = entry.szExePath;
  return true;
}

module_info module_info_from_handle(HMODULE module) {
  module_info out{};
  if (!module) {
    return out;
  }
  char buffer[MAX_PATH] = {};
  const DWORD len = GetModuleFileNameA(module, buffer, MAX_PATH);
  if (len != 0) {
    out.path.assign(buffer, len);
  }
  out.base = module;
  return out;
}

HMODULE find_module_handle(const char* module, module_info& out_info) {
  if (!module || module[0] == '\0') {
    HMODULE handle = GetModuleHandleA(nullptr);
    out_info = module_info_from_handle(handle);
    return handle;
  }

  auto modules = enumerate_modules();
  for (const auto& entry : modules) {
    if (module_matches(module, entry.path)) {
      out_info = entry;
      return reinterpret_cast<HMODULE>(entry.base);
    }
  }

  HMODULE handle = GetModuleHandleA(module);
  out_info = module_info_from_handle(handle);
  return handle;
}

void** resolve_import_from_module(HMODULE module, const char* symbol, const char* import_module) {
  if (!module || !symbol || symbol[0] == '\0') {
    return nullptr;
  }

  auto* base = reinterpret_cast<uint8_t*>(module);
  auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
    return nullptr;
  }

  auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) {
    return nullptr;
  }

  auto& directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (directory.VirtualAddress == 0) {
    return nullptr;
  }

  auto* import_desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + directory.VirtualAddress);
  for (; import_desc->Name != 0; ++import_desc) {
    const char* name = reinterpret_cast<const char*>(base + import_desc->Name);
    if (!module_matches(import_module, name ? std::string(name) : std::string{})) {
      continue;
    }

    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
      auto* thunk_iat = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + import_desc->FirstThunk);
      auto* thunk_orig = import_desc->OriginalFirstThunk != 0
                             ? reinterpret_cast<IMAGE_THUNK_DATA64*>(base + import_desc->OriginalFirstThunk)
                             : nullptr;
      for (; thunk_iat->u1.AddressOfData != 0; ++thunk_iat) {
        auto* thunk_lookup = thunk_orig ? thunk_orig : thunk_iat;
        if (IMAGE_SNAP_BY_ORDINAL64(thunk_lookup->u1.Ordinal)) {
          if (thunk_orig) {
            ++thunk_orig;
          }
          continue;
        }
        auto* import_by_name =
            reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + thunk_lookup->u1.AddressOfData);
        if (import_by_name && std::strcmp(import_by_name->Name, symbol) == 0) {
          return reinterpret_cast<void**>(&thunk_iat->u1.Function);
        }
        if (thunk_orig) {
          ++thunk_orig;
        }
      }
    } else {
      auto* thunk_iat = reinterpret_cast<IMAGE_THUNK_DATA32*>(base + import_desc->FirstThunk);
      auto* thunk_orig = import_desc->OriginalFirstThunk != 0
                             ? reinterpret_cast<IMAGE_THUNK_DATA32*>(base + import_desc->OriginalFirstThunk)
                             : nullptr;
      for (; thunk_iat->u1.AddressOfData != 0; ++thunk_iat) {
        auto* thunk_lookup = thunk_orig ? thunk_orig : thunk_iat;
        if (IMAGE_SNAP_BY_ORDINAL32(thunk_lookup->u1.Ordinal)) {
          if (thunk_orig) {
            ++thunk_orig;
          }
          continue;
        }
        auto* import_by_name =
            reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + thunk_lookup->u1.AddressOfData);
        if (import_by_name && std::strcmp(import_by_name->Name, symbol) == 0) {
          return reinterpret_cast<void**>(&thunk_iat->u1.Function);
        }
        if (thunk_orig) {
          ++thunk_orig;
        }
      }
    }
  }

  return nullptr;
}
#endif

} // namespace

std::vector<module_info> enumerate_modules() {
  std::vector<module_info> modules;
#if defined(_WIN32)
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
  if (snapshot == INVALID_HANDLE_VALUE) {
    return modules;
  }

  MODULEENTRY32 entry{};
  entry.dwSize = sizeof(entry);
  if (Module32First(snapshot, &entry)) {
    do {
      module_info info{};
      module_info_from_entry(entry, info);
      modules.push_back(std::move(info));
    } while (Module32Next(snapshot, &entry));
  }

  CloseHandle(snapshot);
#endif
  return modules;
}

symbol_resolution resolve_symbol(const char* symbol, const char* module) {
  symbol_resolution result{};
#if defined(_WIN32)
  if (!symbol || symbol[0] == '\0') {
    result.error = make_error(hook_error::invalid_target, "missing_symbol");
    return result;
  }

  if (!module || module[0] == '\0') {
    auto modules = enumerate_modules();
    for (const auto& entry : modules) {
      auto* handle = reinterpret_cast<HMODULE>(entry.base);
      auto* address = reinterpret_cast<void*>(GetProcAddress(handle, symbol));
      if (address) {
        result.address = address;
        result.module = entry;
        result.error = make_error(hook_error::ok, nullptr);
        return result;
      }
    }
    result.error = make_error(hook_error::not_found, "symbol_not_found");
    return result;
  }

  module_info module_info{};
  HMODULE handle = find_module_handle(module, module_info);
  if (!handle) {
    result.error = make_error(hook_error::not_found, "module_not_found");
    return result;
  }

  void* address = reinterpret_cast<void*>(GetProcAddress(handle, symbol));
  if (!address) {
    result.error = make_error(hook_error::not_found, "symbol_not_found");
    return result;
  }

  result.address = address;
  result.module = module_info;
  result.error = make_error(hook_error::ok, nullptr);
  return result;
#else
  (void)symbol;
  (void)module;
  result.error = make_error(hook_error::unsupported, "unsupported_platform");
  return result;
#endif
}

symbol_resolution resolve_symbol(const hook_target& target) {
  if (target.kind == hook_target_kind::address) {
    symbol_resolution result{};
    result.address = target.address;
    result.error = make_error(target.address ? hook_error::ok : hook_error::invalid_target, "address_target");
    return result;
  }
  if (target.kind != hook_target_kind::symbol) {
    symbol_resolution result{};
    result.error = make_error(hook_error::invalid_target, "invalid_target_kind");
    return result;
  }
  return resolve_symbol(target.symbol, target.module);
}

import_resolution resolve_import(const char* symbol, const char* module, const char* import_module) {
  import_resolution result{};
#if defined(_WIN32)
  module_info module_info{};
  HMODULE handle = find_module_handle(module, module_info);
  if (!handle) {
    result.error = make_error(hook_error::not_found, "module_not_found");
    return result;
  }

  void** slot = resolve_import_from_module(handle, symbol, import_module);
  if (!slot) {
    result.error = make_error(hook_error::not_found, "import_not_found");
    return result;
  }

  result.slot = slot;
  result.module = module_info;
  result.error = make_error(hook_error::ok, nullptr);
  return result;
#else
  (void)symbol;
  (void)module;
  (void)import_module;
  result.error = make_error(hook_error::unsupported, "unsupported_platform");
  return result;
#endif
}

import_resolution resolve_import(const hook_target& target) {
  if (target.kind != hook_target_kind::import_slot) {
    import_resolution result{};
    result.error = make_error(hook_error::invalid_target, "invalid_target_kind");
    return result;
  }
  if (target.slot) {
    import_resolution result{};
    result.slot = target.slot;
    result.error = make_error(hook_error::ok, nullptr);
    return result;
  }
  return resolve_import(target.symbol, target.module, target.import_module);
}

void* symbol_address(const char* symbol, const char* module) {
  auto resolved = resolve_symbol(symbol, module);
  return resolved.address;
}

} // namespace w1::h00k::resolve
