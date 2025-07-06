#pragma once

#include "../util/module_range_index.hpp"
#include <atomic>
#include <list>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef WITNESS_LIEF_ENABLED
#include <LIEF/LIEF.hpp>
#endif

#ifdef __APPLE__
#include "macos_dyld_resolver.hpp"
#endif

namespace w1::lief {

#ifdef WITNESS_LIEF_ENABLED

// Symbol information
struct symbol_info {
  std::string name;
  std::string demangled_name;
  uint64_t offset; // Offset within module
  uint64_t size;   // Symbol size

  enum type { FUNCTION, OBJECT, UNKNOWN } symbol_type;

  enum binding { LOCAL, GLOBAL, WEAK } symbol_binding;

  std::string version; // Symbol version (Linux)
  std::string section; // Section name

  bool is_exported;
  bool is_imported;
};

class lief_binary_cache;

// Clean, focused symbol resolver
class lief_symbol_resolver {
public:
  // Configuration
  struct config {
    size_t max_cache_size;
    bool prepopulate_exports;
    bool resolve_imports;

    config() : max_cache_size(50), prepopulate_exports(true), resolve_imports(true) {}
  };

  explicit lief_symbol_resolver(const config& cfg = {});
  ~lief_symbol_resolver();

  // Resolve a single address
  std::optional<symbol_info> resolve(uint64_t address, const util::module_range_index& module_index) const;

  // Batch resolution for efficiency
  std::vector<std::optional<symbol_info>> resolve_batch(
      const std::vector<uint64_t>& addresses, const util::module_range_index& module_index
  ) const;

  // Direct module+offset resolution
  std::optional<symbol_info> resolve_in_module(const std::string& module_path, uint64_t offset) const;

  // Get all symbols from a module
  std::vector<symbol_info> get_all_symbols(const std::string& module_path) const;

  // Clear cache
  void clear_cache();

  // Get cache statistics
  struct cache_stats {
    size_t size;
    size_t hits;
    size_t misses;
    double hit_rate;
  };

  cache_stats get_cache_stats() const;

private:
  config config_;
  std::unique_ptr<lief_binary_cache> binary_cache_;

  // Platform-specific resolution
  std::optional<symbol_info> resolve_elf_symbol(LIEF::ELF::Binary* elf, uint64_t offset) const;

  std::optional<symbol_info> resolve_pe_symbol(LIEF::PE::Binary* pe, uint64_t offset) const;

  std::optional<symbol_info> resolve_macho_symbol(LIEF::MachO::Binary* macho, uint64_t offset) const;

  // Conversion helpers
  symbol_info elf_symbol_to_info(const LIEF::ELF::Symbol& sym) const;
  symbol_info pe_export_to_info(const LIEF::PE::ExportEntry& exp) const;
  symbol_info macho_symbol_to_info(const LIEF::MachO::Symbol& sym) const;
};

// Separate binary cache with LRU eviction
class lief_binary_cache {
public:
  explicit lief_binary_cache(size_t max_size = 50);
  ~lief_binary_cache();

  LIEF::Binary* get_or_load(const std::string& path) const;

  void clear();

  lief_symbol_resolver::cache_stats get_stats() const;

#ifdef __APPLE__
  // Set dyld resolver for macOS
  void set_dyld_resolver(std::shared_ptr<macos_dyld_resolver> resolver) { dyld_resolver_ = resolver; }
#endif

private:
  mutable std::list<std::string> lru_list_;
  mutable std::unordered_map<std::string, std::pair<std::list<std::string>::iterator, std::unique_ptr<LIEF::Binary>>>
      cache_;
  mutable std::unordered_set<std::string> failed_paths_; // Cache for paths that failed to load
  mutable std::shared_mutex mutex_;
  size_t max_size_;
  mutable std::atomic<size_t> hits_;
  mutable std::atomic<size_t> misses_;
  mutable std::atomic<size_t> negative_hits_; // Hits on failed path cache

#ifdef __APPLE__
  std::shared_ptr<macos_dyld_resolver> dyld_resolver_;
#endif
};

#else // !WITNESS_LIEF_ENABLED

// Stub implementation when LIEF is disabled
struct symbol_info {
  std::string name = "unknown";
  std::string demangled_name = "unknown";
  uint64_t offset = 0;
  uint64_t size = 0;

  enum type { FUNCTION, OBJECT, UNKNOWN } symbol_type = UNKNOWN;

  enum binding { LOCAL, GLOBAL, WEAK } symbol_binding = LOCAL;

  std::string version;
  std::string section;

  bool is_exported = false;
  bool is_imported = false;
};

class lief_symbol_resolver {
public:
  struct config {
    size_t max_cache_size;
    bool prepopulate_exports;
    bool resolve_imports;

    config() : max_cache_size(50), prepopulate_exports(true), resolve_imports(true) {}
  };

  struct cache_stats {
    size_t size = 0;
    size_t hits = 0;
    size_t misses = 0;
    double hit_rate = 0.0;
  };

  explicit lief_symbol_resolver(const config& cfg = config()) {}

  std::optional<symbol_info> resolve(uint64_t, const util::module_range_index&) const { return std::nullopt; }

  std::optional<symbol_info> resolve_in_module(const std::string&, uint64_t) const { return std::nullopt; }

  std::vector<std::optional<symbol_info>> resolve_batch(
      const std::vector<uint64_t>&, const util::module_range_index&
  ) const {
    return {};
  }

  std::vector<symbol_info> get_all_symbols(const std::string&) const { return {}; }
  void clear_cache() {}
  cache_stats get_cache_stats() const { return {}; }
};

#endif // WITNESS_LIEF_ENABLED

} // namespace w1::lief