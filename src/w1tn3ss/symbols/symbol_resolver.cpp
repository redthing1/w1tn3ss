#include "symbol_resolver.hpp"
#include "lief_symbol_backend.hpp"
#include "path_resolver.hpp"
#include <redlog.hpp>
#include <memory>
#include <vector>

#ifdef _WIN32
#include "windows_symbol_backend.hpp"
#include "windows_path_resolver.hpp"
#else
#include "posix_symbol_backend.hpp"
#ifdef __APPLE__
#include "macos_dyld_resolver.hpp"
#endif
#endif

namespace w1::symbols {

// implementation class to hide backend details
class symbol_resolver::impl {
public:
  explicit impl(const config& cfg);

  // delegated methods
  std::optional<symbol_info> resolve_address(uint64_t address, const util::module_range_index& module_index) const;
  std::vector<std::optional<symbol_info>> resolve_addresses(
      const std::vector<uint64_t>& addresses, const util::module_range_index& module_index
  ) const;
  std::optional<uint64_t> resolve_name(const std::string& name, const std::string& module_hint) const;
  std::vector<symbol_info> find_symbols(const std::string& pattern, const std::string& module_hint) const;
  std::optional<symbol_info> resolve_in_module(const std::string& module_path, uint64_t offset) const;
  std::vector<symbol_info> get_module_symbols(const std::string& module_path) const;
  void clear_cache();
  symbol_resolver::cache_stats get_cache_stats() const;
  std::string get_backend_name() const;
  std::vector<std::string> get_available_backends() const;

private:
  config config_;
  std::shared_ptr<symbol_backend> primary_backend_;
  std::shared_ptr<symbol_backend> fallback_backend_;
  std::shared_ptr<path_resolver> path_resolver_;
  redlog::logger log_;

  // cache statistics
  mutable size_t cache_hits_ = 0;
  mutable size_t cache_misses_ = 0;

  // setup backends based on platform and config
  void setup_backends();
};

// public interface implementation
symbol_resolver::symbol_resolver(const config& cfg) : pimpl_(std::make_unique<impl>(cfg)) {}

symbol_resolver::~symbol_resolver() = default;

std::optional<symbol_info> symbol_resolver::resolve_address(
    uint64_t address, const util::module_range_index& module_index
) const {
  return pimpl_->resolve_address(address, module_index);
}

std::vector<std::optional<symbol_info>> symbol_resolver::resolve_addresses(
    const std::vector<uint64_t>& addresses, const util::module_range_index& module_index
) const {
  return pimpl_->resolve_addresses(addresses, module_index);
}

std::optional<uint64_t> symbol_resolver::resolve_name(const std::string& name, const std::string& module_hint) const {
  return pimpl_->resolve_name(name, module_hint);
}

std::vector<symbol_info> symbol_resolver::find_symbols(
    const std::string& pattern, const std::string& module_hint
) const {
  return pimpl_->find_symbols(pattern, module_hint);
}

std::optional<symbol_info> symbol_resolver::resolve_in_module(const std::string& module_path, uint64_t offset) const {
  return pimpl_->resolve_in_module(module_path, offset);
}

std::vector<symbol_info> symbol_resolver::get_module_symbols(const std::string& module_path) const {
  return pimpl_->get_module_symbols(module_path);
}

void symbol_resolver::clear_cache() { pimpl_->clear_cache(); }

symbol_resolver::cache_stats symbol_resolver::get_cache_stats() const { return pimpl_->get_cache_stats(); }

std::string symbol_resolver::get_backend_name() const { return pimpl_->get_backend_name(); }

std::vector<std::string> symbol_resolver::get_available_backends() const { return pimpl_->get_available_backends(); }

// implementation class methods
symbol_resolver::impl::impl(const config& cfg) : config_(cfg), log_("w1.symbol_resolver") {
  setup_backends();

  log_.inf(
      "initialized symbol resolver",
      redlog::field("primary_backend", primary_backend_ ? primary_backend_->get_name() : "none"),
      redlog::field("fallback_backend", fallback_backend_ ? fallback_backend_->get_name() : "none")
  );
}

void symbol_resolver::impl::setup_backends() {
  // create path resolver
#ifdef _WIN32
  path_resolver_ = std::make_shared<windows_path_resolver>();
#elif defined(__APPLE__)
  path_resolver_ = std::make_shared<macos_dyld_resolver>();
#endif

  // create primary backend based on platform
#ifdef _WIN32
  if (config_.use_native_backend) {
    primary_backend_ = std::make_shared<windows_symbol_backend>();
  }
#else
  if (config_.use_native_backend) {
    primary_backend_ = std::make_shared<posix_symbol_backend>();
  }
#endif

  // create lief backend as fallback if enabled
#ifdef WITNESS_LIEF_ENABLED
  if (config_.use_lief_backend) {
    lief_symbol_backend::config lief_cfg;
    lief_cfg.max_cache_size = config_.max_cache_size;
    lief_cfg.prepopulate_exports = config_.prepopulate_exports;
    lief_cfg.resolve_imports = config_.resolve_imports;
    auto lief_backend = std::make_shared<lief_symbol_backend>(lief_cfg);

    // set path resolver for lief backend
    if (path_resolver_) {
      lief_backend->set_path_resolver(path_resolver_);
    }

    if (!primary_backend_) {
      primary_backend_ = lief_backend;
    } else {
      fallback_backend_ = lief_backend;
    }
  }
#endif

  if (!primary_backend_) {
    log_.err("no symbol backend available");
  }
}

std::optional<symbol_info> symbol_resolver::impl::resolve_address(
    uint64_t address, const util::module_range_index& module_index
) const {

  if (!primary_backend_) {
    return std::nullopt;
  }

  // for native backends, try direct resolution first
  if (auto result = primary_backend_->resolve_address(address)) {
    cache_hits_++;
    return result;
  }

  // for file-based backends (like lief), we need module context
  if (auto module = module_index.find_containing(address)) {
    uint64_t offset = address - module->base_address;

    // resolve module path if needed
    std::string module_path = module->path;
    if (path_resolver_) {
      if (auto resolved = path_resolver_->resolve_library_path(module->path)) {
        module_path = *resolved;
      }
    }

    if (auto result = primary_backend_->resolve_in_module(module_path, offset)) {
      cache_hits_++;
      return result;
    }

    // try fallback backend
    if (fallback_backend_) {
      if (auto result = fallback_backend_->resolve_in_module(module_path, offset)) {
        cache_hits_++;
        return result;
      }
    }
  }

  cache_misses_++;
  return std::nullopt;
}

std::vector<std::optional<symbol_info>> symbol_resolver::impl::resolve_addresses(
    const std::vector<uint64_t>& addresses, const util::module_range_index& module_index
) const {

  std::vector<std::optional<symbol_info>> results;
  results.reserve(addresses.size());

  for (uint64_t addr : addresses) {
    results.push_back(resolve_address(addr, module_index));
  }

  return results;
}

std::optional<uint64_t> symbol_resolver::impl::resolve_name(
    const std::string& name, const std::string& module_hint
) const {
  if (!primary_backend_) {
    return std::nullopt;
  }

  // try primary backend
  if (auto result = primary_backend_->resolve_name(name, module_hint)) {
    return result;
  }

  // try fallback backend
  if (fallback_backend_) {
    return fallback_backend_->resolve_name(name, module_hint);
  }

  return std::nullopt;
}

std::vector<symbol_info> symbol_resolver::impl::find_symbols(
    const std::string& pattern, const std::string& module_hint
) const {
  std::vector<symbol_info> results;

  if (!primary_backend_) {
    return results;
  }

  // get results from primary backend
  auto primary_results = primary_backend_->find_symbols(pattern, module_hint);
  results.insert(results.end(), primary_results.begin(), primary_results.end());

  // add results from fallback backend if available
  if (fallback_backend_) {
    auto fallback_results = fallback_backend_->find_symbols(pattern, module_hint);

    // deduplicate based on symbol name
    for (const auto& sym : fallback_results) {
      bool found = false;
      for (const auto& existing : results) {
        if (existing.name == sym.name) {
          found = true;
          break;
        }
      }
      if (!found) {
        results.push_back(sym);
      }
    }
  }

  return results;
}

std::optional<symbol_info> symbol_resolver::impl::resolve_in_module(
    const std::string& module_path, uint64_t offset
) const {
  if (!primary_backend_) {
    return std::nullopt;
  }

  // resolve module path if needed
  std::string resolved_path = module_path;
  if (path_resolver_) {
    if (auto resolved = path_resolver_->resolve_library_path(module_path)) {
      resolved_path = *resolved;
    }
  }

  // try primary backend
  if (auto result = primary_backend_->resolve_in_module(resolved_path, offset)) {
    return result;
  }

  // try fallback backend
  if (fallback_backend_) {
    return fallback_backend_->resolve_in_module(resolved_path, offset);
  }

  return std::nullopt;
}

std::vector<symbol_info> symbol_resolver::impl::get_module_symbols(const std::string& module_path) const {
  if (!primary_backend_) {
    return {};
  }

  // resolve module path if needed
  std::string resolved_path = module_path;
  if (path_resolver_) {
    if (auto resolved = path_resolver_->resolve_library_path(module_path)) {
      resolved_path = *resolved;
    }
  }

  // prefer backend that supports file resolution for complete symbol list
  if (fallback_backend_ && fallback_backend_->get_capabilities().supports_file_resolution) {
    return fallback_backend_->get_module_symbols(resolved_path);
  }

  return primary_backend_->get_module_symbols(resolved_path);
}

void symbol_resolver::impl::clear_cache() {
  if (primary_backend_) {
    primary_backend_->clear_cache();
  }
  if (fallback_backend_) {
    fallback_backend_->clear_cache();
  }
  cache_hits_ = 0;
  cache_misses_ = 0;
}

symbol_resolver::cache_stats symbol_resolver::impl::get_cache_stats() const {
  size_t total = cache_hits_ + cache_misses_;
  return {
      .size = 0, // backends manage their own caches
      .hits = cache_hits_,
      .misses = cache_misses_,
      .hit_rate = total > 0 ? double(cache_hits_) / double(total) : 0.0
  };
}

std::string symbol_resolver::impl::get_backend_name() const {
  if (primary_backend_) {
    std::string name = primary_backend_->get_name();
    if (fallback_backend_) {
      name += "+" + fallback_backend_->get_name();
    }
    return name;
  }
  return "none";
}

std::vector<std::string> symbol_resolver::impl::get_available_backends() const {
  std::vector<std::string> backends;

  if (primary_backend_ && primary_backend_->is_available()) {
    backends.push_back(primary_backend_->get_name());
  }
  if (fallback_backend_ && fallback_backend_->is_available()) {
    backends.push_back(fallback_backend_->get_name());
  }

  return backends;
}

} // namespace w1::symbols