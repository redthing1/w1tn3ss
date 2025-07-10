#pragma once

#include "symbol_backend.hpp"
#include "symbol_info.hpp"
#include <atomic>
#include <list>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <redlog.hpp>
#include <unordered_map>
#include <unordered_set>

#ifdef WITNESS_LIEF_ENABLED
#include <LIEF/LIEF.hpp>
#endif

namespace w1::symbols {

class lief_binary_cache;
class path_resolver;

/**
 * @brief lief-based symbol resolution backend
 *
 * uses LIEF library to parse binary formats and resolve symbols.
 * supports ELF, PE, and MachO formats.
 */
class lief_symbol_backend : public symbol_backend {
public:
  struct config {
    size_t max_cache_size;
    bool prepopulate_exports;
    bool resolve_imports;

    config() : max_cache_size(50), prepopulate_exports(true), resolve_imports(true) {}
  };

  explicit lief_symbol_backend(const config& cfg = {});
  ~lief_symbol_backend();

  // symbol_backend interface
  std::optional<symbol_info> resolve_address(uint64_t address) const override;
  std::optional<uint64_t> resolve_name(const std::string& name, const std::string& module_hint = "") const override;
  std::optional<symbol_info> resolve_in_module(const std::string& module_path, uint64_t offset) const override;
  std::vector<symbol_info> find_symbols(const std::string& pattern, const std::string& module_hint = "") const override;
  std::vector<symbol_info> get_module_symbols(const std::string& module_path) const override;

  std::string get_name() const override { return "lief"; }
  bool is_available() const override;
  capabilities get_capabilities() const override;
  void clear_cache() override;

  // set path resolver for finding binaries
  void set_path_resolver(std::shared_ptr<path_resolver> resolver);

#ifdef WITNESS_LIEF_ENABLED
private:
  // platform-specific resolution
  std::optional<symbol_info> resolve_elf_symbol(LIEF::ELF::Binary* elf, uint64_t offset) const;
  std::optional<symbol_info> resolve_pe_symbol(LIEF::PE::Binary* pe, uint64_t offset) const;
  std::optional<symbol_info> resolve_macho_symbol(LIEF::MachO::Binary* macho, uint64_t offset) const;

  // symbol name resolution
  std::optional<uint64_t> find_symbol_in_elf(LIEF::ELF::Binary* elf, const std::string& name) const;
  std::optional<uint64_t> find_symbol_in_pe(LIEF::PE::Binary* pe, const std::string& name) const;
  std::optional<uint64_t> find_symbol_in_macho(LIEF::MachO::Binary* macho, const std::string& name) const;

  // pattern matching
  std::vector<symbol_info> find_symbols_in_elf(LIEF::ELF::Binary* elf, const std::string& pattern) const;
  std::vector<symbol_info> find_symbols_in_pe(LIEF::PE::Binary* pe, const std::string& pattern) const;
  std::vector<symbol_info> find_symbols_in_macho(LIEF::MachO::Binary* macho, const std::string& pattern) const;

  // conversion helpers
  symbol_info elf_symbol_to_info(const LIEF::ELF::Symbol& sym) const;
  symbol_info pe_export_to_info(const LIEF::PE::ExportEntry& exp) const;
  symbol_info macho_symbol_to_info(const LIEF::MachO::Symbol& sym) const;

  // pattern matching helper
  bool matches_pattern(const std::string& name, const std::string& pattern) const;
#endif

private:
  config config_;
  std::unique_ptr<lief_binary_cache> binary_cache_;
  std::shared_ptr<path_resolver> path_resolver_;
  redlog::logger log_;
};

/**
 * @brief lru cache for lief binaries
 */
class lief_binary_cache {
public:
  explicit lief_binary_cache(size_t max_size = 50);
  ~lief_binary_cache();

#ifdef WITNESS_LIEF_ENABLED
  LIEF::Binary* get_or_load(const std::string& path) const;
#endif

  void clear();

  struct cache_stats {
    size_t size;
    size_t hits;
    size_t misses;
    double hit_rate;
  };

  cache_stats get_stats() const;

private:
#ifdef WITNESS_LIEF_ENABLED
  mutable std::list<std::string> lru_list_;
  mutable std::unordered_map<std::string, std::pair<std::list<std::string>::iterator, std::unique_ptr<LIEF::Binary>>>
      cache_;
#endif
  mutable std::unordered_set<std::string> failed_paths_;
  mutable std::shared_mutex mutex_;
  size_t max_size_;
  mutable std::atomic<size_t> hits_;
  mutable std::atomic<size_t> misses_;
  mutable std::atomic<size_t> negative_hits_;
  redlog::logger log_;
};

} // namespace w1::symbols