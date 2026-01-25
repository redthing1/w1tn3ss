#include "w1analysis/symbol_lookup.hpp"

#include <cstdlib>
#include <cstring>

#if !defined(_WIN32)
#include <dlfcn.h>
#endif

#if defined(__APPLE__) || defined(__linux__)
#include <cxxabi.h>
#endif

namespace w1::analysis {

symbol_lookup::symbol_lookup(const runtime::module_catalog* modules, symbol_lookup_config config)
    : modules_(modules), config_(config) {}

void symbol_lookup::set_module_catalog(const runtime::module_catalog* modules) { modules_ = modules; }

void symbol_lookup::set_config(symbol_lookup_config config) { config_ = config; }

std::optional<symbol_info> symbol_lookup::resolve(uint64_t address) const {
  if (config_.enable_cache) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto it = cache_.find(address);
    if (it != cache_.end()) {
      return it->second;
    }
  }

  if (!modules_) {
    return std::nullopt;
  }

  auto module = modules_->find_containing(address);
  if (!module) {
    return std::nullopt;
  }

  symbol_info info{};
  info.address = address;
  info.module_name = module->name;
  info.module_path = module->path;
  info.module_offset = address - module->base_address;

  if (auto native = resolve_native(address)) {
    info.symbol_name = native->symbol_name;
    info.demangled_name = native->demangled_name;
    info.symbol_address = native->symbol_address;
    info.symbol_offset = native->symbol_address ? (address - native->symbol_address) : 0;
    info.is_exported = native->is_exported;
    info.is_imported = native->is_imported;
    info.has_symbol = !info.symbol_name.empty();
  }

  std::optional<symbol_info> result = info;

  if (config_.enable_cache) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    if (cache_.size() >= config_.max_cache_entries) {
      cache_.clear();
    }
    cache_[address] = result;
  }

  return result;
}

std::vector<std::optional<symbol_info>> symbol_lookup::resolve_many(const std::vector<uint64_t>& addresses) const {
  std::vector<std::optional<symbol_info>> results;
  results.reserve(addresses.size());

  for (uint64_t address : addresses) {
    results.push_back(resolve(address));
  }

  return results;
}

void symbol_lookup::clear_cache() {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  cache_.clear();
}

size_t symbol_lookup::cache_size() const {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  return cache_.size();
}

std::optional<symbol_lookup::native_symbol_result> symbol_lookup::resolve_native(uint64_t address) const {
#if !defined(_WIN32)
  Dl_info info;
  std::memset(&info, 0, sizeof(info));

  if (dladdr(reinterpret_cast<void*>(address), &info) == 0) {
    return std::nullopt;
  }

  native_symbol_result result{};
  if (info.dli_sname) {
    result.symbol_name = info.dli_sname;
    result.demangled_name = maybe_demangle(info.dli_sname);
    result.is_exported = true;
  } else {
    result.demangled_name.clear();
  }

  if (info.dli_saddr) {
    result.symbol_address = reinterpret_cast<uint64_t>(info.dli_saddr);
  }

  return result;
#else
  (void) address;
  return std::nullopt;
#endif
}

std::string symbol_lookup::maybe_demangle(const char* name) const {
  if (!config_.enable_demangle || !name) {
    return name ? std::string{name} : std::string{};
  }

#if defined(__APPLE__) || defined(__linux__)
  int status = 0;
  char* demangled = abi::__cxa_demangle(name, nullptr, nullptr, &status);
  if (status == 0 && demangled) {
    std::string result{demangled};
    std::free(demangled);
    return result;
  }
  std::free(demangled);
#endif

  return std::string{name};
}

} // namespace w1::analysis
