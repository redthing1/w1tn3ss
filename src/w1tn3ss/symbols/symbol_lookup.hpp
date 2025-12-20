#pragma once

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <w1tn3ss/util/module_range_index.hpp>

#include "symbol_resolver.hpp"

namespace w1::symbols {

class symbol_lookup {
public:
  struct symbol_context {
    std::string module_name;
    std::string symbol_name;
    std::string demangled_name;
    uint64_t symbol_offset = 0;
    uint64_t module_offset = 0;
    bool is_exported = false;
    bool is_imported = false;
  };

  struct cache_stats {
    size_t binary_cache_size = 0;
    size_t binary_cache_hits = 0;
    size_t binary_cache_misses = 0;
    double hit_rate = 0.0;
  };

  symbol_lookup();
  explicit symbol_lookup(const symbol_resolver::config& config);

  void initialize(const util::module_range_index& module_index);

  std::optional<symbol_context> resolve(uint64_t address) const;
  std::vector<std::optional<symbol_context>> resolve_many(const std::vector<uint64_t>& addresses) const;

  void clear_cache();
  cache_stats get_cache_stats() const;

private:
  std::unique_ptr<symbol_resolver> resolver_;
  const util::module_range_index* module_index_ = nullptr;

  mutable std::unordered_map<uint64_t, std::optional<symbol_context>> symbol_cache_;
  mutable std::mutex symbol_cache_mutex_;
  static constexpr size_t max_symbol_cache_size = 10000;

  symbol_context to_context(
      uint64_t address, const util::module_info& module, const symbol_info& symbol
  ) const;
};

} // namespace w1::symbols
