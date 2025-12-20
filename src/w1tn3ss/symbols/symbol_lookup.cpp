#include "symbol_lookup.hpp"

namespace w1::symbols {

symbol_lookup::symbol_lookup() {
  symbol_resolver::config cfg;
  cfg.max_cache_size = 100;
  cfg.prepopulate_exports = true;
  cfg.resolve_imports = true;
  resolver_ = std::make_unique<symbol_resolver>(cfg);
}

symbol_lookup::symbol_lookup(const symbol_resolver::config& config) {
  resolver_ = std::make_unique<symbol_resolver>(config);
}

void symbol_lookup::initialize(const util::module_range_index& module_index) { module_index_ = &module_index; }

std::optional<symbol_lookup::symbol_context> symbol_lookup::resolve(uint64_t address) const {
  {
    std::lock_guard<std::mutex> lock(symbol_cache_mutex_);
    auto it = symbol_cache_.find(address);
    if (it != symbol_cache_.end()) {
      return it->second;
    }
  }

  if (!resolver_ || !module_index_) {
    return std::nullopt;
  }

  auto module = module_index_->find_containing(address);
  if (!module) {
    return std::nullopt;
  }

  uint64_t module_offset = address - module->base_address;
  auto symbol = resolver_->resolve_address(address, *module_index_);

  std::optional<symbol_context> result;
  if (symbol) {
    result = to_context(address, *module, *symbol);
  } else {
    symbol_context ctx;
    ctx.module_name = module->name;
    ctx.module_offset = module_offset;
    result = ctx;
  }

  {
    std::lock_guard<std::mutex> lock(symbol_cache_mutex_);
    if (symbol_cache_.size() >= max_symbol_cache_size) {
      symbol_cache_.clear();
    }
    symbol_cache_[address] = result;
  }

  return result;
}

std::vector<std::optional<symbol_lookup::symbol_context>> symbol_lookup::resolve_many(
    const std::vector<uint64_t>& addresses
) const {
  std::vector<std::optional<symbol_context>> results;
  results.reserve(addresses.size());

  if (!resolver_ || !module_index_) {
    results.resize(addresses.size());
    return results;
  }

  auto symbols = resolver_->resolve_addresses(addresses, *module_index_);

  for (size_t i = 0; i < addresses.size(); ++i) {
    if (!symbols[i]) {
      if (auto module = module_index_->find_containing(addresses[i])) {
        symbol_context ctx;
        ctx.module_name = module->name;
        ctx.module_offset = addresses[i] - module->base_address;
        results.push_back(ctx);
      } else {
        results.push_back(std::nullopt);
      }
    } else {
      if (auto module = module_index_->find_containing(addresses[i])) {
        results.push_back(to_context(addresses[i], *module, *symbols[i]));
      } else {
        results.push_back(std::nullopt);
      }
    }
  }

  return results;
}

void symbol_lookup::clear_cache() {
  if (resolver_) {
    resolver_->clear_cache();
  }
  std::lock_guard<std::mutex> lock(symbol_cache_mutex_);
  symbol_cache_.clear();
}

symbol_lookup::cache_stats symbol_lookup::get_cache_stats() const {
  cache_stats stats;

  if (resolver_) {
    auto resolver_stats = resolver_->get_cache_stats();
    stats.binary_cache_size = resolver_stats.size;
    stats.binary_cache_hits = resolver_stats.hits;
    stats.binary_cache_misses = resolver_stats.misses;
    stats.hit_rate = resolver_stats.hit_rate;
  }

  return stats;
}

symbol_lookup::symbol_context symbol_lookup::to_context(
    uint64_t address, const util::module_info& module, const symbol_info& symbol
) const {
  symbol_context ctx;
  ctx.module_name = module.name;
  ctx.symbol_name = symbol.name;
  ctx.demangled_name = symbol.demangled_name;
  ctx.module_offset = symbol.module_offset ? symbol.module_offset : (address - module.base_address);
  ctx.symbol_offset = symbol.offset_from_symbol;
  ctx.is_exported = symbol.is_exported;
  ctx.is_imported = symbol.is_imported;
  return ctx;
}

} // namespace w1::symbols
