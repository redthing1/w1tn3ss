#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "w1runtime/module_catalog.hpp"

namespace w1::analysis {

struct symbol_info {
  std::string module_name;
  std::string module_path;
  std::string symbol_name;
  std::string demangled_name;
  uint64_t address = 0;
  uint64_t module_offset = 0;
  uint64_t symbol_address = 0;
  uint64_t symbol_offset = 0;
  bool is_exported = false;
  bool is_imported = false;
  bool has_symbol = false;
};

struct symbol_lookup_config {
  size_t max_cache_entries = 10000;
  bool enable_cache = true;
  bool enable_demangle = true;
};

class symbol_lookup {
public:
  symbol_lookup() = default;
  explicit symbol_lookup(const runtime::module_catalog* modules, symbol_lookup_config config = {});

  void set_module_catalog(const runtime::module_catalog* modules);
  void set_config(symbol_lookup_config config);

  std::optional<symbol_info> resolve(uint64_t address) const;
  std::vector<std::optional<symbol_info>> resolve_many(const std::vector<uint64_t>& addresses) const;

  void clear_cache();
  size_t cache_size() const;

private:
  struct native_symbol_result {
    std::string symbol_name;
    std::string demangled_name;
    uint64_t symbol_address = 0;
    bool is_exported = false;
    bool is_imported = false;
  };

  std::optional<native_symbol_result> resolve_native(uint64_t address) const;
  std::string maybe_demangle(const char* name) const;

  const runtime::module_catalog* modules_ = nullptr;
  symbol_lookup_config config_{};

  mutable std::unordered_map<uint64_t, std::optional<symbol_info>> cache_{};
  mutable std::mutex cache_mutex_{};
};

} // namespace w1::analysis
