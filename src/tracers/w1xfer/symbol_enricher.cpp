#include "symbol_enricher.hpp"
#include <redlog.hpp>

namespace w1xfer {

symbol_enricher::symbol_enricher() {
  log_.inf("creating unified symbol resolver");

  w1::symbols::symbol_resolver::config cfg;
  cfg.max_cache_size = 100; // cache more binaries for transfer analysis
  cfg.prepopulate_exports = true;
  cfg.resolve_imports = true;

  resolver_ = std::make_unique<w1::symbols::symbol_resolver>(cfg);
}

symbol_enricher::~symbol_enricher() = default;

void symbol_enricher::initialize(const w1::util::module_range_index& module_index) {
  log_.dbg("initializing symbol enricher with module index", redlog::field("module_count", module_index.size()));
  module_index_ = &module_index;
}

std::optional<symbol_enricher::symbol_context> symbol_enricher::enrich_address(uint64_t address) const {
  // check symbol cache first
  {
    std::lock_guard<std::mutex> lock(symbol_cache_mutex_);
    auto it = symbol_cache_.find(address);
    if (it != symbol_cache_.end()) {
      return it->second;
    }
  }

  if (!resolver_ || !module_index_) {
    log_.err("no resolver or module index available");
    return std::nullopt;
  }

  // find which module contains this address
  auto module = module_index_->find_containing(address);
  if (!module) {
    log_.dbg("no module found for address", redlog::field("address", "0x%016llx", address));
    return std::nullopt;
  }

  // calculate offset within module
  uint64_t module_offset = address - module->base_address;
  log_.trc(
      "resolving symbol", redlog::field("address", "0x%016llx", address), redlog::field("module_name", module->name),
      redlog::field("module_path", module->path), redlog::field("module_offset", "0x%016llx", module_offset)
  );

  log_.dbg(
      "calling unified symbol resolver", redlog::field("address", "0x%016llx", address),
      redlog::field("module", module->name)
  );

  auto symbol = resolver_->resolve_address(address, *module_index_);

  if (!symbol) {
    log_.dbg("no symbol found", redlog::field("address", "0x%016llx", address), redlog::field("module", module->name));

    // return basic context with module info
    symbol_context ctx;
    ctx.module_name = module->name;
    ctx.module_offset = module_offset;

    // cache the result
    {
      std::lock_guard<std::mutex> lock(symbol_cache_mutex_);
      if (symbol_cache_.size() >= MAX_SYMBOL_CACHE_SIZE) {
        symbol_cache_.clear();
      }
      symbol_cache_[address] = ctx;
    }

    return ctx;
  }

  log_.trc(
      "symbol resolved", redlog::field("address", "0x%016llx", address), redlog::field("symbol_name", symbol->name),
      redlog::field("demangled_name", symbol->demangled_name),
      redlog::field("offset_from_symbol", "0x%016llx", symbol->offset_from_symbol),
      redlog::field("is_exported", symbol->is_exported)
  );

  auto result = to_context(address, *module, *symbol);

  // cache the result
  {
    std::lock_guard<std::mutex> lock(symbol_cache_mutex_);
    // implement simple LRU by clearing cache when it gets too large
    // this is a simple but effective cache management strategy
    // when cache is full, we clear it entirely rather than tracking individual item ages
    if (symbol_cache_.size() >= MAX_SYMBOL_CACHE_SIZE) {
      symbol_cache_.clear();
    }
    symbol_cache_[address] = result;
  }

  return result;
}

std::vector<std::optional<symbol_enricher::symbol_context>> symbol_enricher::enrich_addresses(
    const std::vector<uint64_t>& addresses
) const {
  if (!resolver_ || !module_index_) {
    return std::vector<std::optional<symbol_context>>(addresses.size());
  }

  // use batch resolution for efficiency
  auto symbols = resolver_->resolve_addresses(addresses, *module_index_);

  std::vector<std::optional<symbol_context>> results;
  results.reserve(addresses.size());

  for (size_t i = 0; i < addresses.size(); ++i) {
    if (!symbols[i]) {
      // try to at least get module info
      if (auto module = module_index_->find_containing(addresses[i])) {
        symbol_context ctx;
        ctx.module_name = module->name;
        ctx.module_offset = addresses[i] - module->base_address;
        results.push_back(ctx);
      } else {
        results.push_back(std::nullopt);
      }
    } else {
      // we have symbol info
      auto module = module_index_->find_containing(addresses[i]);
      if (module) {
        results.push_back(to_context(addresses[i], *module, *symbols[i]));
      } else {
        results.push_back(std::nullopt);
      }
    }
  }

  return results;
}

void symbol_enricher::clear_cache() {
  if (resolver_) {
    resolver_->clear_cache();
  }
  std::lock_guard<std::mutex> lock(symbol_cache_mutex_);
  symbol_cache_.clear();
}

symbol_enricher::cache_stats symbol_enricher::get_cache_stats() const {
  cache_stats stats{};

  if (resolver_) {
    auto resolver_stats = resolver_->get_cache_stats();
    stats.binary_cache_size = resolver_stats.size;
    stats.binary_cache_hits = resolver_stats.hits;
    stats.binary_cache_misses = resolver_stats.misses;
    stats.hit_rate = resolver_stats.hit_rate;
  }

  return stats;
}

symbol_enricher::symbol_context symbol_enricher::to_context(
    uint64_t address, const w1::util::module_info& module, const w1::symbols::symbol_info& symbol
) const {

  symbol_context ctx;
  ctx.module_name = module.name;
  ctx.symbol_name = symbol.name;
  ctx.demangled_name = symbol.demangled_name;
  // use module_offset from symbol if available, otherwise calculate it
  ctx.module_offset = symbol.module_offset ? symbol.module_offset : (address - module.base_address);
  // symbol_offset is the offset from the start of the symbol
  // offset_from_symbol already contains this value from the resolver
  ctx.symbol_offset = symbol.offset_from_symbol;
  ctx.is_exported = symbol.is_exported;
  ctx.is_imported = symbol.is_imported;

  return ctx;
}

} // namespace w1xfer