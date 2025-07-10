#ifdef _WIN32

#include "windows_symbol_backend.hpp"
#include "windows_path_resolver.hpp"

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#endif
#include <algorithm>
#include <cctype>

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

namespace w1::symbols {

// static members
std::once_flag windows_symbol_backend::init_flag_;
bool windows_symbol_backend::init_success_ = false;

windows_symbol_backend::windows_symbol_backend() : log_("w1.windows_symbol_backend") {
  // initialization happens on first use
}

windows_symbol_backend::~windows_symbol_backend() = default;

bool windows_symbol_backend::is_available() const {
  return true; // windows backend is always available on windows
}

windows_symbol_backend::capabilities windows_symbol_backend::get_capabilities() const {
  return {
      .supports_runtime_resolution = true,
      .supports_file_resolution = false, // dbghelp works with loaded modules
      .supports_pattern_matching = true,
      .supports_demangling = true
  };
}

std::optional<symbol_info> windows_symbol_backend::resolve_address(uint64_t address) const {
  auto win_info = resolve_symbol_info_native(address);
  if (!win_info) {
    return std::nullopt;
  }

  return convert_to_symbol_info(*win_info);
}

std::optional<uint64_t> windows_symbol_backend::resolve_name(
    const std::string& name, const std::string& module_hint
) const {
  static HANDLE process_handle = GetCurrentProcess();

  // ensure dbghelp is initialized
  std::call_once(init_flag_, [this]() {
    log_.dbg("initializing winapi symbol handler");

    DWORD options = SymGetOptions();
    options |= SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES;
    options |= SYMOPT_INCLUDE_32BIT_MODULES;
    options |= SYMOPT_CASE_INSENSITIVE;
    SymSetOptions(options);

    if (!SymInitialize(process_handle, NULL, TRUE)) {
      DWORD error = GetLastError();
      log_.err("failed to initialize symbol handler", redlog::field("error", error));
      init_success_ = false;
      return;
    }

    log_.trc("winapi symbol handler initialized");
    init_success_ = true;
  });

  if (!init_success_) {
    return std::nullopt;
  }

  // if module hint provided, get specific module base
  DWORD64 module_base = 0;
  if (!module_hint.empty()) {
    ModuleHandle hmodule = get_module_handle_safe(module_hint);
    if (hmodule) {
      module_base = reinterpret_cast<DWORD64>(hmodule);
    }
  }

  // try to find symbol
  SYMBOL_INFO symbol_info = {};
  symbol_info.SizeOfStruct = sizeof(SYMBOL_INFO);

  if (SymFromName(process_handle, name.c_str(), &symbol_info)) {
    // if module hint was provided, verify the symbol is from that module
    if (module_base != 0) {
      IMAGEHLP_MODULE64 module_info = {};
      module_info.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
      if (SymGetModuleInfo64(process_handle, symbol_info.Address, &module_info)) {
        if (module_info.BaseOfImage != module_base) {
          // symbol found but in wrong module
          return std::nullopt;
        }
      }
    }

    log_.dbg(
        "resolved symbol by name", redlog::field("name", name), redlog::field("address", "0x%llx", symbol_info.Address)
    );
    return symbol_info.Address;
  }

  return std::nullopt;
}

std::optional<symbol_info> windows_symbol_backend::resolve_in_module(
    const std::string& module_path, uint64_t offset
) const {
  log_.trc(
      "resolving symbol in module", redlog::field("module_path", module_path), redlog::field("offset", "0x%llx", offset)
  );

  // get module handle
  ModuleHandle module_handle = get_module_handle_safe(module_path);
  if (!module_handle) {
    log_.trc("module not loaded", redlog::field("module_path", module_path));
    return std::nullopt;
  }

  // get module base address
  MODULEINFO module_info;
  if (!GetModuleInformation(
          GetCurrentProcess(), static_cast<HMODULE>(module_handle), &module_info, sizeof(module_info)
      )) {
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
  return resolve_address(absolute_address);
}

// callback context for symbol enumeration
struct enum_context {
  std::vector<symbol_info>* symbols;
  const std::string* pattern;
  windows_symbol_backend* backend;
};

BOOL CALLBACK
windows_symbol_backend::enum_symbols_callback(PSYMBOL_INFO symbol_info, ULONG symbol_size, PVOID user_context) {
  auto* ctx = static_cast<enum_context*>(user_context);

  // convert windows symbol info to our format
  windows_symbol_info win_info;
  win_info.name = symbol_info->Name;
  win_info.address = symbol_info->Address;
  win_info.size = symbol_info->Size;
  win_info.displacement = 0;
  win_info.is_function =
      (symbol_info->Tag == SymTagFunction || symbol_info->Tag == SymTagPublicSymbol ||
       (symbol_info->Flags & SYMFLAG_FUNCTION));
  win_info.is_exported = (symbol_info->Flags & SYMFLAG_EXPORT);

  // get module info
  IMAGEHLP_MODULE64 module_info = {};
  module_info.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
  if (SymGetModuleInfo64(GetCurrentProcess(), symbol_info->Address, &module_info)) {
    win_info.module_name = module_info.ModuleName;
  }

  // demangle if needed
  win_info.demangled_name = win_info.name;
  char demangled_buffer[MAX_SYM_NAME] = {};
  DWORD demangled_length = UnDecorateSymbolName(
      win_info.name.c_str(), demangled_buffer, MAX_SYM_NAME, UNDNAME_COMPLETE | UNDNAME_NO_LEADING_UNDERSCORES
  );
  if (demangled_length > 0 && demangled_buffer[0] != '\0') {
    win_info.demangled_name = std::string(demangled_buffer, demangled_length);
  }

  // check pattern match if provided
  if (ctx->pattern && !ctx->pattern->empty()) {
    // simple wildcard matching (TODO: could be improved)
    std::string pattern = *ctx->pattern;
    std::string name_lower = win_info.demangled_name;
    std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
    std::transform(pattern.begin(), pattern.end(), pattern.begin(), ::tolower);

    bool matches = false;
    if (pattern.front() == '*' && pattern.back() == '*') {
      // *substring*
      matches = name_lower.find(pattern.substr(1, pattern.length() - 2)) != std::string::npos;
    } else if (pattern.back() == '*') {
      // prefix*
      matches = name_lower.find(pattern.substr(0, pattern.length() - 1)) == 0;
    } else if (pattern.front() == '*') {
      // *suffix
      std::string suffix = pattern.substr(1);
      matches = name_lower.length() >= suffix.length() &&
                name_lower.compare(name_lower.length() - suffix.length(), suffix.length(), suffix) == 0;
    } else {
      // exact match
      matches = name_lower == pattern;
    }

    if (!matches) {
      return TRUE; // continue enumeration
    }
  }

  ctx->symbols->push_back(ctx->backend->convert_to_symbol_info(win_info));

  return TRUE; // continue enumeration
}

std::vector<symbol_info> windows_symbol_backend::find_symbols(
    const std::string& pattern, const std::string& module_hint
) const {
  std::vector<symbol_info> results;

  static HANDLE process_handle = GetCurrentProcess();

  // ensure dbghelp is initialized
  std::call_once(init_flag_, [this]() {
    log_.dbg("initializing winapi symbol handler");

    DWORD options = SymGetOptions();
    options |= SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES;
    options |= SYMOPT_INCLUDE_32BIT_MODULES;
    options |= SYMOPT_CASE_INSENSITIVE;
    SymSetOptions(options);

    if (!SymInitialize(process_handle, NULL, TRUE)) {
      DWORD error = GetLastError();
      log_.err("failed to initialize symbol handler", redlog::field("error", error));
      init_success_ = false;
      return;
    }

    log_.trc("winapi symbol handler initialized");
    init_success_ = true;
  });

  if (!init_success_) {
    return results;
  }

  enum_context ctx = {&results, &pattern, const_cast<windows_symbol_backend*>(this)};

  // if module hint provided, enumerate only that module
  if (!module_hint.empty()) {
    ModuleHandle hmodule = get_module_handle_safe(module_hint);
    if (hmodule) {
      DWORD64 base = reinterpret_cast<DWORD64>(hmodule);
      SymEnumSymbols(process_handle, base, nullptr, enum_symbols_callback, &ctx);
    }
  } else {
    // enumerate all modules
    SymEnumSymbols(process_handle, 0, nullptr, enum_symbols_callback, &ctx);
  }

  log_.dbg("found symbols matching pattern", redlog::field("pattern", pattern), redlog::field("count", results.size()));

  return results;
}

std::vector<symbol_info> windows_symbol_backend::get_module_symbols(const std::string& module_path) const {
  // use find_symbols with empty pattern to get all symbols
  return find_symbols("", module_path);
}

void windows_symbol_backend::clear_cache() {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  module_cache_.clear();
  log_.dbg("windows symbol backend cache cleared");
}

std::optional<windows_symbol_backend::windows_symbol_info> windows_symbol_backend::resolve_symbol_info_native(
    uint64_t address
) const {
  static HANDLE process_handle = GetCurrentProcess();

  // thread-safe initialization using std::call_once
  std::call_once(init_flag_, [this]() {
    log_.dbg("initializing winapi symbol handler");

    DWORD options = SymGetOptions();
    options |= SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES;
    options |= SYMOPT_INCLUDE_32BIT_MODULES;
    options |= SYMOPT_CASE_INSENSITIVE;
    SymSetOptions(options);

    if (!SymInitialize(process_handle, NULL, TRUE)) {
      DWORD error = GetLastError();
      log_.err("failed to initialize symbol handler", redlog::field("error", error));
      init_success_ = false;
      return;
    }

    log_.trc("winapi symbol handler initialized");
    init_success_ = true;
  });

  // check if initialization succeeded
  if (!init_success_) {
    log_.trc("symbol handler initialization failed, cannot resolve symbols");
    return std::nullopt;
  }

  // allocate buffer for symbol info
  const size_t buffer_size = sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR);
  char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
  PSYMBOL_INFO symbol_info = (PSYMBOL_INFO) buffer;

  symbol_info->SizeOfStruct = sizeof(SYMBOL_INFO);
  symbol_info->MaxNameLen = MAX_SYM_NAME;

  DWORD64 displacement = 0;

  log_.ped("calling SymFromAddr", redlog::field("address", "0x%llx", address));

  if (SymFromAddr(process_handle, address, &displacement, symbol_info)) {
    windows_symbol_info result;

    // basic symbol information
    if (symbol_info->NameLen > 0 && symbol_info->Name) {
      result.name.assign(symbol_info->Name, symbol_info->NameLen);
    } else {
      result.name.clear();
    }
    result.address = symbol_info->Address;
    result.size = symbol_info->Size;
    result.displacement = displacement;

    // get module information
    IMAGEHLP_MODULE64 module_info = {};
    module_info.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    if (SymGetModuleInfo64(process_handle, address, &module_info)) {
      result.module_name = std::string(module_info.ModuleName);
      log_.ped("retrieved module info", redlog::field("module", result.module_name));
    } else {
      result.module_name.clear();
    }

    // determine symbol type
    result.is_function =
        (symbol_info->Tag == SymTagFunction || symbol_info->Tag == SymTagPublicSymbol ||
         (symbol_info->Flags & SYMFLAG_FUNCTION));

    result.is_exported = (symbol_info->Flags & SYMFLAG_EXPORT);

    // try to get demangled name
    result.demangled_name = result.name; // fallback
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
        redlog::field("size", result.size), redlog::field("module", result.module_name)
    );

    return result;
  } else {
    DWORD error = GetLastError();
    log_.ped("SymFromAddr failed", redlog::field("address", "0x%llx", address), redlog::field("error", error));
    return std::nullopt;
  }
}

symbol_info windows_symbol_backend::convert_to_symbol_info(const windows_symbol_info& win_info) const {
  symbol_info info{};

  // copy string fields
  info.name = win_info.name;
  info.demangled_name = win_info.demangled_name;
  info.section = win_info.module_name;

  // ensure we have at least a name
  if (info.name.empty()) {
    info.name = "sub_" + std::to_string(win_info.address);
  }

  // handle numeric fields
  info.size = win_info.size;
  info.offset = win_info.displacement;

  // map symbol type
  info.symbol_type = win_info.is_function ? symbol_info::type::FUNCTION : symbol_info::type::OBJECT;

  // windows resolved symbols are typically global scope
  info.symbol_binding = symbol_info::binding::GLOBAL;

  // copy boolean flags
  info.is_exported = win_info.is_exported;
  info.is_imported = false; // SymFromAddr resolves actual symbols, not import stubs

  // version field is typically empty for windows symbols
  info.version.clear();

  return info;
}

ModuleHandle windows_symbol_backend::get_module_handle_safe(const std::string& module_name) const {
  // check cache first
  {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto it = module_cache_.find(module_name);
    if (it != module_cache_.end()) {
      return it->second;
    }
  }

  // try to get module handle
  HMODULE handle = GetModuleHandleA(module_name.c_str());

  if (!handle) {
    // try with just basename if full path was provided
    std::string basename = module_name;
    size_t last_slash = basename.find_last_of("\\/");
    if (last_slash != std::string::npos) {
      basename = basename.substr(last_slash + 1);
      handle = GetModuleHandleA(basename.c_str());
    }
  }

  // cache the result if found
  ModuleHandle result = static_cast<ModuleHandle>(handle);
  if (result) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    module_cache_[module_name] = result;
  }

  return result;
}

} // namespace w1::symbols

#endif // _WIN32