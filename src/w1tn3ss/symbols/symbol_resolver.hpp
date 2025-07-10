#pragma once

#include "symbol_info.hpp"
#include "symbol_backend.hpp"
#include "util/module_range_index.hpp"
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace w1::symbols {

/**
 * @brief main symbol resolution interface
 *
 * provides high-level symbol resolution functionality with automatic
 * backend selection based on platform and availability.
 */
class symbol_resolver {
public:
  /**
   * @brief configuration for symbol resolver
   */
  struct config {
    size_t max_cache_size;
    bool use_native_backend; // prefer native APIs when available
    bool use_lief_backend;   // use LIEF as fallback
    bool enable_caching;
    bool prepopulate_exports;
    bool resolve_imports;

    config()
        : max_cache_size(100), use_native_backend(true), use_lief_backend(true), enable_caching(true),
          prepopulate_exports(true), resolve_imports(true) {}
  };

  explicit symbol_resolver(const config& cfg = {});
  ~symbol_resolver();

  // address to symbol resolution

  /**
   * @brief resolve symbol at absolute address
   * @param address absolute memory address to resolve
   * @param module_index module range index for address lookup
   * @return symbol information if found
   */
  std::optional<symbol_info> resolve_address(uint64_t address, const util::module_range_index& module_index) const;

  /**
   * @brief batch symbol resolution for efficiency
   * @param addresses vector of absolute addresses to resolve
   * @param module_index module range index for address lookup
   * @return vector of symbol information (nullopt for unresolved addresses)
   */
  std::vector<std::optional<symbol_info>> resolve_addresses(
      const std::vector<uint64_t>& addresses, const util::module_range_index& module_index
  ) const;

  // symbol name to address resolution

  /**
   * @brief resolve symbol address by name
   * @param name symbol name to look up
   * @param module_hint optional module name to search in (empty = search all loaded modules)
   * @return absolute address if found
   */
  std::optional<uint64_t> resolve_name(const std::string& name, const std::string& module_hint = "") const;

  /**
   * @brief find symbols matching pattern
   * @param pattern wildcard pattern (e.g. "malloc*", "*printf")
   * @param module_hint optional module to search in
   * @return vector of matching symbols
   */
  std::vector<symbol_info> find_symbols(const std::string& pattern, const std::string& module_hint = "") const;

  // module-specific operations

  /**
   * @brief resolve symbol in specific module at offset
   * @param module_path path to module (may be basename on Windows)
   * @param offset offset within module
   * @return symbol information if found
   */
  std::optional<symbol_info> resolve_in_module(const std::string& module_path, uint64_t offset) const;

  /**
   * @brief get all symbols from a module
   * @param module_path path to module
   * @return vector of all symbols in module
   */
  std::vector<symbol_info> get_module_symbols(const std::string& module_path) const;

  // cache management

  /**
   * @brief clear all internal caches
   */
  void clear_cache();

  /**
   * @brief cache statistics
   */
  struct cache_stats {
    size_t size;
    size_t hits;
    size_t misses;
    double hit_rate;
  };

  /**
   * @brief get cache statistics
   * @return current cache performance metrics
   */
  cache_stats get_cache_stats() const;

  // backend information

  /**
   * @brief get active backend name
   * @return name of the backend being used
   */
  std::string get_backend_name() const;

  /**
   * @brief check which backends are available
   * @return list of available backend names
   */
  std::vector<std::string> get_available_backends() const;

private:
  class impl;
  std::unique_ptr<impl> pimpl_;
};

} // namespace w1::symbols