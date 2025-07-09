#include "symbol_resolver.hpp"
#include "symbol_info.hpp"
#include <redlog.hpp>

namespace w1::lief {

symbol_resolver::symbol_resolver(const config& cfg)
#ifdef _WIN32
    : windows_backend_()
#else
    : lief_backend_([&cfg]() {
        lief_symbol_resolver::config lief_cfg;
        lief_cfg.max_cache_size = cfg.max_cache_size;
        lief_cfg.prepopulate_exports = cfg.prepopulate_exports;
        lief_cfg.resolve_imports = cfg.resolve_imports;
        return lief_cfg;
      }())
#endif
{
  static redlog::logger log("w1.symbol_resolver");
  log.inf(
      "initialized unified symbol resolver", redlog::field(
                                                 "backend",
#ifdef _WIN32
                                                 "windows_native"
#else
                                                 "lief"
#endif
                                             )
  );
}

symbol_resolver::~symbol_resolver() = default;

std::optional<symbol_info> symbol_resolver::resolve(
    uint64_t address, const util::module_range_index& module_index
) const {
#ifdef _WIN32
  // Windows: Use native resolution directly with absolute address
  return windows_backend_.resolve_symbol_native(address);
#else
  // Other platforms: Use LIEF with module index
  return lief_backend_.resolve(address, module_index);
#endif
}

std::vector<std::optional<symbol_info>> symbol_resolver::resolve_batch(
    const std::vector<uint64_t>& addresses, const util::module_range_index& module_index
) const {
#ifdef _WIN32
  // Windows: Use native batch resolution
  std::vector<std::optional<symbol_info>> results;
  results.reserve(addresses.size());

  for (uint64_t address : addresses) {
    results.push_back(windows_backend_.resolve_symbol_native(address));
  }

  return results;
#else
  // Other platforms: Use LIEF batch resolution
  return lief_backend_.resolve_batch(addresses, module_index);
#endif
}

std::optional<symbol_info> symbol_resolver::resolve_in_module(const std::string& module_path, uint64_t offset) const {
#ifdef _WIN32
  // Windows: Use native Windows backend with module+offset resolution
  return windows_backend_.resolve_in_module(module_path, offset);
#else
  // Other platforms: Use LIEF directly
  return lief_backend_.resolve_in_module(module_path, offset);
#endif
}

std::vector<symbol_info> symbol_resolver::get_all_symbols(const std::string& module_path) const {
#ifdef _WIN32
  // Windows: Not easily supported by SymFromAddr - would need symbol enumeration
  static redlog::logger log("w1.symbol_resolver");
  log.trc("Windows get_all_symbols not implemented - native APIs don't easily support this");
  return {};
#else
  // Other platforms: Use LIEF
  return lief_backend_.get_all_symbols(module_path);
#endif
}

void symbol_resolver::clear_cache() {
#ifdef _WIN32
  windows_backend_.clear_cache();
#else
  lief_backend_.clear_cache();
#endif
}

symbol_resolver::cache_stats symbol_resolver::get_cache_stats() const {
#ifdef _WIN32
  // Windows backend doesn't currently expose cache stats
  // Could be added to windows_system_resolver later
  return {0, 0, 0, 0.0};
#else
  auto stats = lief_backend_.get_cache_stats();
  return {stats.size, stats.hits, stats.misses, stats.hit_rate};
#endif
}

} // namespace w1::lief