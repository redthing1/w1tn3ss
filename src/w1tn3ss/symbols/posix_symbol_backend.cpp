#if !defined(_WIN32)

#include "posix_symbol_backend.hpp"
#include <dlfcn.h>
#include <cstring>
#include <filesystem>

namespace w1::symbols {

namespace fs = std::filesystem;

posix_symbol_backend::posix_symbol_backend() : log_("w1.posix_symbol_backend") {
  log_.dbg("initialized posix symbol backend");
}

posix_symbol_backend::~posix_symbol_backend() {
  // close all cached handles
  std::lock_guard<std::mutex> lock(cache_mutex_);
  for (auto& [path, handle] : handle_cache_) {
    if (handle && handle != RTLD_DEFAULT && handle != RTLD_NEXT) {
      dlclose(handle);
    }
  }
}

posix_symbol_backend::capabilities posix_symbol_backend::get_capabilities() const {
  return {
      .supports_runtime_resolution = true,
      .supports_file_resolution = true,   // can dlopen files
      .supports_pattern_matching = false, // no native pattern support
      .supports_demangling = false        // dladdr doesn't demangle
  };
}

std::optional<symbol_info> posix_symbol_backend::resolve_address(uint64_t address) const {
  Dl_info info;
  memset(&info, 0, sizeof(info));

  if (dladdr(reinterpret_cast<void*>(address), &info) == 0) {
    log_.trc("dladdr failed for address", redlog::field("address", "0x%llx", address));
    return std::nullopt;
  }

  log_.dbg(
      "dladdr success", redlog::field("address", "0x%llx", address),
      redlog::field("symbol", info.dli_sname ? info.dli_sname : "<null>"),
      redlog::field("module", info.dli_fname ? info.dli_fname : "<null>")
  );

  return dladdr_to_symbol_info(&info, address);
}

std::optional<uint64_t> posix_symbol_backend::resolve_name(
    const std::string& name, const std::string& module_hint
) const {
  void* handle = RTLD_DEFAULT;

  if (!module_hint.empty()) {
    handle = open_module(module_hint);
    if (!handle) {
      log_.trc(
          "failed to open module for symbol lookup", redlog::field("module", module_hint), redlog::field("name", name)
      );
      return std::nullopt;
    }
  }

  // look up symbol
  void* sym_addr = dlsym(handle, name.c_str());
  if (!sym_addr) {
    const char* error = dlerror();
    log_.trc("dlsym failed", redlog::field("name", name), redlog::field("error", error ? error : "<null>"));
    return std::nullopt;
  }

  uint64_t address = reinterpret_cast<uint64_t>(sym_addr);
  log_.dbg("resolved symbol by name", redlog::field("name", name), redlog::field("address", "0x%llx", address));

  return address;
}

std::optional<symbol_info> posix_symbol_backend::resolve_in_module(
    const std::string& module_path, uint64_t offset
) const {
  // for posix, we need the absolute address, not just offset
  // try to get module base address
  void* handle = open_module(module_path);
  if (!handle) {
    log_.trc("failed to open module", redlog::field("module", module_path));
    return std::nullopt;
  }

  // there's no portable way to get module base address from dlopen handle
  // so we use a workaround: look up a known symbol and use dladdr

  // try to find any exported symbol to get module info
  Dl_info module_info;
  memset(&module_info, 0, sizeof(module_info));

  // on linux, we can try to look up the module's init function
  void* init_addr = dlsym(handle, "_init");
  if (init_addr && dladdr(init_addr, &module_info) != 0) {
    // calculate absolute address
    uint64_t base = reinterpret_cast<uint64_t>(module_info.dli_fbase);
    uint64_t absolute_addr = base + offset;

    log_.trc(
        "calculated absolute address from module base", redlog::field("module", module_path),
        redlog::field("base", "0x%llx", base), redlog::field("offset", "0x%llx", offset),
        redlog::field("absolute", "0x%llx", absolute_addr)
    );

    return resolve_address(absolute_addr);
  }

  log_.trc("could not determine module base address", redlog::field("module", module_path));
  return std::nullopt;
}

std::vector<symbol_info> posix_symbol_backend::find_symbols(
    const std::string& pattern, const std::string& module_hint
) const {
  // posix APIs don't support symbol enumeration or pattern matching
  log_.trc("posix backend does not support pattern-based symbol search", redlog::field("pattern", pattern));
  return {};
}

std::vector<symbol_info> posix_symbol_backend::get_module_symbols(const std::string& module_path) const {
  // posix APIs don't support symbol enumeration
  log_.trc("posix backend does not support module symbol enumeration", redlog::field("module", module_path));
  return {};
}

void posix_symbol_backend::clear_cache() {
  std::lock_guard<std::mutex> lock(cache_mutex_);

  // close all handles except special ones
  for (auto& [path, handle] : handle_cache_) {
    if (handle && handle != RTLD_DEFAULT && handle != RTLD_NEXT) {
      dlclose(handle);
    }
  }

  handle_cache_.clear();
  log_.dbg("posix symbol backend cache cleared");
}

void* posix_symbol_backend::open_module(const std::string& module_path) const {
  // check cache first
  {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto it = handle_cache_.find(module_path);
    if (it != handle_cache_.end()) {
      return it->second;
    }
  }

  // try to open the module
  void* handle = nullptr;

  // if it's a full path, use it directly
  if (module_path.find('/') != std::string::npos) {
    handle = dlopen(module_path.c_str(), RTLD_LAZY | RTLD_LOCAL);
  } else {
    // it's just a name, let dlopen search for it
    handle = dlopen(module_path.c_str(), RTLD_LAZY | RTLD_LOCAL);
  }

  if (!handle) {
    const char* error = dlerror();
    log_.trc("dlopen failed", redlog::field("module", module_path), redlog::field("error", error ? error : "<null>"));
    return nullptr;
  }

  // cache the handle
  {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    handle_cache_[module_path] = handle;
  }

  return handle;
}

symbol_info posix_symbol_backend::dladdr_to_symbol_info(const void* addr_info, uint64_t query_address) const {
  const Dl_info* info = static_cast<const Dl_info*>(addr_info);
  symbol_info sym;

  // symbol name
  if (info->dli_sname) {
    sym.name = info->dli_sname;
    sym.demangled_name = info->dli_sname; // dladdr doesn't demangle
  } else {
    // no symbol name, generate one
    sym.name = "sub_" + std::to_string(query_address);
    sym.demangled_name = sym.name;
  }

  // module name
  if (info->dli_fname) {
    // extract just the filename
    std::string full_path = info->dli_fname;
    size_t last_slash = full_path.find_last_of('/');
    if (last_slash != std::string::npos) {
      sym.section = full_path.substr(last_slash + 1);
    } else {
      sym.section = full_path;
    }
  }

  // calculate offset from symbol start
  if (info->dli_saddr) {
    uint64_t sym_addr = reinterpret_cast<uint64_t>(info->dli_saddr);
    sym.offset = query_address - sym_addr;
  } else {
    sym.offset = 0;
  }

  // dladdr doesn't provide size information
  sym.size = 0;

  // assume function type for resolved symbols
  sym.symbol_type = symbol_info::FUNCTION;
  sym.symbol_binding = symbol_info::GLOBAL;

  // dladdr only resolves exported symbols
  sym.is_exported = true;
  sym.is_imported = false;

  return sym;
}

} // namespace w1::symbols

#endif // !_WIN32