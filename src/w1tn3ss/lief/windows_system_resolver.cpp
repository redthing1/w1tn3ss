#ifdef _WIN32

#include "windows_system_resolver.hpp"
#include <windows.h>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <dbghelp.h>
#include <psapi.h>
#include <mutex>

// define SymTag constants since cvconst.h might not be available
#ifndef SymTagFunction
enum SymTagEnum {
  SymTagNull,
  SymTagExe,
  SymTagCompiland,
  SymTagCompilandDetails,
  SymTagCompilandEnv,
  SymTagFunction,
  SymTagBlock,
  SymTagData,
  SymTagAnnotation,
  SymTagLabel,
  SymTagPublicSymbol,
  SymTagUDT,
  SymTagEnum,
  SymTagFunctionType,
  SymTagPointerType,
  SymTagArrayType,
  SymTagBaseType,
  SymTagTypedef,
  SymTagBaseClass,
  SymTagFriend,
  SymTagFunctionArgType,
  SymTagFuncDebugStart,
  SymTagFuncDebugEnd,
  SymTagUsingNamespace,
  SymTagVTableShape,
  SymTagVTable,
  SymTagCustom,
  SymTagThunk,
  SymTagCustomType,
  SymTagManagedType,
  SymTagDimension,
  SymTagCallSite,
  SymTagInlineSite,
  SymTagBaseInterface,
  SymTagVectorType,
  SymTagMatrixType,
  SymTagHLSLType,
  SymTagCaller,
  SymTagCallee,
  SymTagExport,
  SymTagHeapAllocationSite,
  SymTagCoffGroup,
  SymTagMax
};
#endif

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

namespace w1::lief {

namespace fs = std::filesystem;

windows_system_resolver::windows_system_resolver() : log_("w1.windows_system_resolver") {
  log_.dbg("initializing windows system resolver");

  system_directories_ = discover_system_directories();

  if (system_directories_.empty()) {
    log_.err("failed to discover any windows system directories");
  } else {
    log_.trc("windows system resolver initialized", redlog::field("system_directories", system_directories_.size()));

    for (const auto& dir : system_directories_) {
      log_.dbg("system directory", redlog::field("path", dir));
    }
  }
}

std::optional<std::string> windows_system_resolver::resolve_system_library(const std::string& basename) const {
  if (basename.empty() || !is_available()) {
    return std::nullopt;
  }

  // normalize basename for consistent caching
  std::string norm_basename = normalize_basename(basename);

  log_.trc(
      "attempting to resolve system library", redlog::field("basename", basename),
      redlog::field("normalized", norm_basename)
  );

  // check if this looks like a system library
  if (!is_likely_system_library(norm_basename)) {
    log_.trc("not a likely system library", redlog::field("basename", norm_basename));
    return std::nullopt;
  }

  // check cache first
  {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto it = path_cache_.find(norm_basename);
    if (it != path_cache_.end()) {
      log_.dbg(
          "windows resolver cache hit", redlog::field("basename", norm_basename),
          redlog::field("cached_path", it->second), redlog::field("cache_size", path_cache_.size())
      );
      return it->second;
    }
    log_.dbg(
        "windows resolver cache miss", redlog::field("basename", norm_basename),
        redlog::field("cache_size", path_cache_.size())
    );
  }

  // search in system directories
  auto resolved_path = find_in_system_directories(norm_basename);

  if (resolved_path) {
    log_.dbg(
        "resolved system library", redlog::field("basename", basename), redlog::field("resolved_path", *resolved_path)
    );

    // cache the result
    {
      std::lock_guard<std::mutex> lock(cache_mutex_);
      path_cache_[norm_basename] = *resolved_path;
    }

    return resolved_path;
  }

  log_.trc("system library not found", redlog::field("basename", basename));
  return std::nullopt;
}

std::vector<std::string> windows_system_resolver::discover_system_directories() const {
  std::vector<std::string> directories;

  log_.dbg("discovering windows system directories");

  // get system32 directory
  wchar_t system32_path[MAX_PATH];
  UINT system32_len = GetSystemDirectoryW(system32_path, MAX_PATH);
  if (system32_len > 0 && system32_len < MAX_PATH) {
    // convert wide string to narrow string
    char narrow_path[MAX_PATH];
    int converted = WideCharToMultiByte(CP_UTF8, 0, system32_path, -1, narrow_path, MAX_PATH, nullptr, nullptr);
    if (converted > 0) {
      std::string system32_str(narrow_path);
      directories.push_back(system32_str);
      log_.dbg("found system32 directory", redlog::field("path", system32_str));
    }
  }

  // get windows directory
  wchar_t windows_path[MAX_PATH];
  UINT windows_len = GetWindowsDirectoryW(windows_path, MAX_PATH);
  if (windows_len > 0 && windows_len < MAX_PATH) {
    char narrow_path[MAX_PATH];
    int converted = WideCharToMultiByte(CP_UTF8, 0, windows_path, -1, narrow_path, MAX_PATH, nullptr, nullptr);
    if (converted > 0) {
      std::string windows_str(narrow_path);
      directories.push_back(windows_str);
      log_.dbg("found windows directory", redlog::field("path", windows_str));
    }
  }

  // add syswow64 directory (for 32-bit dlls on 64-bit systems)
  if (!directories.empty()) {
    // construct syswow64 path from windows directory
    wchar_t syswow64_path[MAX_PATH];
    if (windows_len > 0) {
      // replace "System32" with "SysWOW64" in windows path, or append it
      std::wstring windows_wide(windows_path);
      std::wstring syswow64_wide = windows_wide + L"\\SysWOW64";

      if (syswow64_wide.length() < MAX_PATH) {
        wcscpy_s(syswow64_path, MAX_PATH, syswow64_wide.c_str());

        char narrow_path[MAX_PATH];
        int converted = WideCharToMultiByte(CP_UTF8, 0, syswow64_path, -1, narrow_path, MAX_PATH, nullptr, nullptr);
        if (converted > 0) {
          std::string syswow64_str(narrow_path);
          // check if directory exists before adding
          if (fs::exists(syswow64_str) && fs::is_directory(syswow64_str)) {
            directories.push_back(syswow64_str);
            log_.dbg("found syswow64 directory", redlog::field("path", syswow64_str));
          }
        }
      }
    }
  }

  log_.trc("system directory discovery complete", redlog::field("directories_found", directories.size()));

  return directories;
}

std::optional<std::string> windows_system_resolver::find_in_system_directories(const std::string& basename) const {
  log_.trc(
      "searching for library in system directories", redlog::field("basename", basename),
      redlog::field("directories_to_search", system_directories_.size())
  );

  for (const auto& dir : system_directories_) {
    std::string full_path = dir + "\\" + basename;

    log_.trc("checking path", redlog::field("full_path", full_path));

    try {
      if (fs::exists(full_path) && fs::is_regular_file(full_path)) {
        log_.dbg("found library file", redlog::field("basename", basename), redlog::field("full_path", full_path));
        return full_path;
      }
    } catch (const fs::filesystem_error& e) {
      log_.warn(
          "filesystem error while checking path", redlog::field("path", full_path), redlog::field("error", e.what())
      );
      continue;
    }
  }

  log_.trc("library not found in any system directory", redlog::field("basename", basename));
  return std::nullopt;
}

std::string windows_system_resolver::normalize_basename(const std::string& basename) const {
  std::string normalized = basename;

  // convert to lowercase for case-insensitive matching
  std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](char c) { return std::tolower(c); });

  return normalized;
}

bool windows_system_resolver::is_likely_system_library(const std::string& basename) const {
  if (basename.empty()) {
    return false;
  }

  // must be a dll
  if (basename.find(".dll") == std::string::npos) {
    return false;
  }

  // common windows system library patterns
  static const std::vector<std::string> system_patterns = {
      "kernel32.dll", "ntdll.dll", "user32.dll",   "gdi32.dll",      "advapi32.dll", "shell32.dll",
      "shlwapi.dll",  "ole32.dll", "oleaut32.dll", "rpcrt4.dll",     "ucrtbase.dll", "msvcrt.dll",
      "msvcp",        "vcruntime", "api-ms-win-",  "kernelbase.dll", "sechost.dll",  "comctl32.dll",
      "ws2_32.dll",   "winmm.dll", "version.dll",  "imm32.dll",      "setupapi.dll"
  };

  std::string lower_basename = normalize_basename(basename);

  for (const auto& pattern : system_patterns) {
    if (lower_basename.find(pattern) == 0 || lower_basename == pattern) {
      log_.trc(
          "matched system library pattern", redlog::field("basename", basename), redlog::field("pattern", pattern)
      );
      return true;
    }
  }

  log_.trc("no system library pattern match", redlog::field("basename", basename));
  return false;
}

std::optional<windows_symbol_info> windows_system_resolver::resolve_symbol_info_native(uint64_t address) const {
  static std::once_flag init_flag;
  static HANDLE process_handle = GetCurrentProcess();
  static bool init_success = false;

  // thread-safe initialization using std::call_once
  std::call_once(init_flag, [this]() {
    log_.dbg("initializing winapi symbol handler");

    DWORD options = SymGetOptions();
    options |= SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES;
    options |= SYMOPT_INCLUDE_32BIT_MODULES; // include 32-bit modules on 64-bit systems
    options |= SYMOPT_CASE_INSENSITIVE;      // case insensitive symbol searches
    SymSetOptions(options);

    if (!SymInitialize(process_handle, NULL, TRUE)) {
      DWORD error = GetLastError();
      log_.err("failed to initialize symbol handler", redlog::field("error", error));
      init_success = false;
      return;
    }

    log_.trc("winapi symbol handler initialized");
    init_success = true;
  });

  // check if initialization succeeded
  if (!init_success) {
    log_.trc("symbol handler initialization failed, cannot resolve symbols");
    return std::nullopt;
  }

  // Allocate buffer for symbol info
  const size_t buffer_size = sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR);
  char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
  PSYMBOL_INFO symbol_info = (PSYMBOL_INFO) buffer;

  symbol_info->SizeOfStruct = sizeof(SYMBOL_INFO);
  symbol_info->MaxNameLen = MAX_SYM_NAME;

  DWORD64 displacement = 0;

  log_.ped("calling SymFromAddr", redlog::field("address", "0x%llx", address));

  if (SymFromAddr(process_handle, address, &displacement, symbol_info)) {
    windows_symbol_info result;

    // basic symbol information - ensure proper string construction
    if (symbol_info->NameLen > 0 && symbol_info->Name) {
      result.name.assign(symbol_info->Name, symbol_info->NameLen);
    } else {
      result.name.clear();
    }
    result.address = symbol_info->Address;
    result.size = symbol_info->Size;
    result.displacement = displacement;

    // get module information with proper string handling
    IMAGEHLP_MODULE64 module_info = {};
    module_info.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    if (SymGetModuleInfo64(process_handle, address, &module_info)) {
      result.module_name = std::string(module_info.ModuleName);
      log_.ped("retrieved module info", redlog::field("module", result.module_name));
    } else {
      result.module_name.clear();
    }

    // determine symbol type based on flags
    result.is_function =
        (symbol_info->Tag == SymTagFunction || symbol_info->Tag == SymTagPublicSymbol ||
         (symbol_info->Flags & SYMFLAG_FUNCTION));

    result.is_exported = (symbol_info->Flags & SYMFLAG_EXPORT);

    // try to get demangled name (C++ symbols) with proper error handling
    result.demangled_name = result.name; // fallback to original name
    if (!result.name.empty()) {
      char demangled_buffer[MAX_SYM_NAME] = {};
      DWORD demangled_length = UnDecorateSymbolName(
          result.name.c_str(), demangled_buffer, MAX_SYM_NAME, UNDNAME_COMPLETE | UNDNAME_NO_LEADING_UNDERSCORES
      );
      if (demangled_length > 0 && demangled_buffer[0] != '\0') {
        result.demangled_name = std::string(demangled_buffer, demangled_length);
      }
    }

    log_.ped(
        "SymFromAddr success", redlog::field("address", "0x%llx", address), redlog::field("symbol", result.name),
        redlog::field("demangled", result.demangled_name), redlog::field("displacement", displacement),
        redlog::field("size", result.size), redlog::field("module", result.module_name),
        redlog::field("is_function", result.is_function), redlog::field("is_exported", result.is_exported),
        redlog::field("tag", symbol_info->Tag), redlog::field("flags", "0x%x", symbol_info->Flags)
    );

    return result;
  } else {
    DWORD error = GetLastError();
    log_.ped("SymFromAddr failed", redlog::field("address", "0x%llx", address), redlog::field("error", error));
    return std::nullopt;
  }
}

std::optional<std::string> windows_system_resolver::resolve_symbol_name_native(uint64_t address) const {
  auto symbol_info = resolve_symbol_info_native(address);
  if (!symbol_info || symbol_info->name.empty()) {
    return std::nullopt;
  }

  std::string symbol_name = symbol_info->name;

  // if there's displacement, add it to symbol name for precise location
  if (symbol_info->displacement > 0) {
    symbol_name += "+" + std::to_string(symbol_info->displacement);
  }

  return symbol_name;
}

std::optional<symbol_info> windows_system_resolver::resolve_symbol_native(uint64_t address) const {
  auto win_symbol = resolve_symbol_info_native(address);
  if (!win_symbol) {
    log_.dbg("native winapi symbol resolution failed", redlog::field("address", "0x%llx", address));
    return std::nullopt;
  }

  log_.dbg(
      "resolved symbol using native winapi", redlog::field("address", "0x%llx", address),
      redlog::field("symbol", win_symbol->name), redlog::field("demangled", win_symbol->demangled_name),
      redlog::field("module", win_symbol->module_name), redlog::field("size", win_symbol->size),
      redlog::field("displacement", win_symbol->displacement)
  );

  // convert Windows symbol info to cross-platform symbol_info
  symbol_info info{};

  // copy string fields with validation (both source and dest are std::string)
  info.name = win_symbol->name;
  info.demangled_name = win_symbol->demangled_name;
  info.section = win_symbol->module_name;

  // ensure we have at least a name for a valid symbol
  if (info.name.empty()) {
    log_.dbg("symbol name is empty, using address as fallback", redlog::field("address", "0x%llx", address));
    info.name = "sub_" + std::to_string(address);
  }

  // handle numeric fields with proper validation
  info.size = win_symbol->size;

  // for offset: Windows SymFromAddr gives displacement from symbol start
  // this is exactly what we want for the offset field
  info.offset = win_symbol->displacement;

  // map Windows symbol type to cross-platform enum
  info.symbol_type = win_symbol->is_function ? symbol_info::type::FUNCTION : symbol_info::type::OBJECT;

  // Windows resolved symbols are typically global scope
  info.symbol_binding = symbol_info::binding::GLOBAL;

  // copy boolean flags directly (both are bool)
  info.is_exported = win_symbol->is_exported;
  info.is_imported = false; // SymFromAddr resolves actual symbols, not import stubs

  // version field is typically empty for Windows symbols
  info.version.clear();

  return info;
}

std::optional<symbol_info> windows_system_resolver::resolve_in_module(
    const std::string& module_path, uint64_t offset
) const {
  log_.trc(
      "resolving symbol in module", redlog::field("module_path", module_path), redlog::field("offset", "0x%llx", offset)
  );

  // first, try to find the module base address
  HANDLE process_handle = GetCurrentProcess();
  HMODULE module_handle = nullptr;

  // try different approaches to get module handle
  std::string search_path = module_path;

  // if it's just a basename, try to resolve it to full path
  if (module_path.find('\\') == std::string::npos && module_path.find('/') == std::string::npos) {
    if (auto resolved = resolve_system_library(module_path)) {
      search_path = *resolved;
      log_.trc(
          "resolved module basename to full path", redlog::field("basename", module_path),
          redlog::field("full_path", search_path)
      );
    }
  }

  // try to get module handle by name
  module_handle = GetModuleHandleA(search_path.c_str());
  if (!module_handle) {
    // try with just the basename
    std::string basename = module_path;
    size_t last_slash = basename.find_last_of("\\/");
    if (last_slash != std::string::npos) {
      basename = basename.substr(last_slash + 1);
    }
    module_handle = GetModuleHandleA(basename.c_str());

    if (!module_handle) {
      log_.trc("module not loaded", redlog::field("module_path", module_path));
      return std::nullopt;
    }
  }

  // get module base address
  MODULEINFO module_info;
  if (!GetModuleInformation(process_handle, module_handle, &module_info, sizeof(module_info))) {
    DWORD error = GetLastError();
    log_.trc(
        "failed to get module information", redlog::field("module_path", module_path), redlog::field("error", error)
    );
    return std::nullopt;
  }

  uint64_t module_base = reinterpret_cast<uint64_t>(module_info.lpBaseOfDll);
  uint64_t absolute_address = module_base + offset;

  log_.trc(
      "calculated absolute address", redlog::field("module_base", "0x%llx", module_base),
      redlog::field("offset", "0x%llx", offset), redlog::field("absolute_address", "0x%llx", absolute_address)
  );

  // now resolve the symbol at the absolute address
  return resolve_symbol_native(absolute_address);
}

void windows_system_resolver::clear_cache() {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  path_cache_.clear();
  log_.dbg("winapi resolver cache cleared");
}

} // namespace w1::lief

#endif // _WIN32