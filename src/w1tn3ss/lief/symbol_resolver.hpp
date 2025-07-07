#pragma once

#include "util/module_range_index.hpp"
#include "symbol_info.hpp"
#include <optional>
#include <string>
#include <vector>

#ifdef _WIN32
#include "windows_system_resolver.hpp"
#else
#include "lief_symbol_resolver.hpp"
#endif

namespace w1::lief {

/**
 * @brief Unified symbol resolver with platform-specific backends
 * @details Zero-cost abstraction that uses optimal resolution method per platform:
 * - Windows: Native SymFromAddr API
 * - Other platforms: LIEF-based resolution
 */
class symbol_resolver {
private:
#ifdef _WIN32
  windows_system_resolver windows_backend_;
#else
  lief_symbol_resolver lief_backend_;
#endif

public:
  /**
   * @brief Configuration for symbol resolver
   */
  struct config {
    size_t max_cache_size;
    bool prepopulate_exports;
    bool resolve_imports;

    config() : max_cache_size(50), prepopulate_exports(true), resolve_imports(true) {}
  };

  explicit symbol_resolver(const config& cfg = {});
  ~symbol_resolver();

  /**
   * @brief Resolve symbol at absolute address
   * @param address absolute memory address to resolve
   * @param module_index module range index for address lookup
   * @return symbol information if found, nullopt otherwise
   */
  std::optional<symbol_info> resolve(uint64_t address, const util::module_range_index& module_index) const;

  /**
   * @brief Batch symbol resolution for efficiency
   * @param addresses vector of absolute addresses to resolve
   * @param module_index module range index for address lookup
   * @return vector of symbol information (nullopt for unresolved addresses)
   */
  std::vector<std::optional<symbol_info>> resolve_batch(
      const std::vector<uint64_t>& addresses, const util::module_range_index& module_index
  ) const;

  /**
   * @brief Direct module+offset resolution
   * @param module_path path to module (may be basename on Windows)
   * @param offset offset within module
   * @return symbol information if found, nullopt otherwise
   */
  std::optional<symbol_info> resolve_in_module(const std::string& module_path, uint64_t offset) const;

  /**
   * @brief Get all symbols from a module
   * @param module_path path to module
   * @return vector of all symbols in module
   */
  std::vector<symbol_info> get_all_symbols(const std::string& module_path) const;

  /**
   * @brief Clear internal caches
   */
  void clear_cache();

  /**
   * @brief Cache statistics
   */
  struct cache_stats {
    size_t size;
    size_t hits;
    size_t misses;
    double hit_rate;
  };

  /**
   * @brief Get cache statistics
   * @return current cache performance metrics
   */
  cache_stats get_cache_stats() const;
};

} // namespace w1::lief