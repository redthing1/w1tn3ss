#include "symbol_enricher.hpp"
#include <redlog.hpp>

namespace w1xfer {

symbol_enricher::symbol_enricher() {
  auto log = redlog::get_logger("w1xfer::symbol_enricher");

#ifdef WITNESS_LIEF_ENABLED
  log.info("creating LIEF symbol resolver with enhanced config");

  w1::lief::lief_symbol_resolver::config cfg;
  cfg.max_cache_size = 100; // Cache more binaries for transfer analysis
  cfg.prepopulate_exports = true;
  cfg.resolve_imports = true;

  resolver_ = std::make_unique<w1::lief::lief_symbol_resolver>(cfg);
#else
  log.warn("LIEF support not enabled, symbol resolution will be limited");
#endif
}

symbol_enricher::~symbol_enricher() = default;

void symbol_enricher::initialize(const w1::util::module_range_index& module_index) {
  auto log = redlog::get_logger("w1xfer::symbol_enricher");
  log.dbg("initializing symbol enricher with module index", redlog::field("module_count", module_index.size()));
  module_index_ = &module_index;
}

std::optional<symbol_enricher::symbol_context> symbol_enricher::enrich_address(uint64_t address) const {
#ifdef WITNESS_LIEF_ENABLED
  auto log = redlog::get_logger("w1xfer::symbol_enricher");

  // Check symbol cache first
  {
    std::lock_guard<std::mutex> lock(symbol_cache_mutex_);
    auto it = symbol_cache_.find(address);
    if (it != symbol_cache_.end()) {
      return it->second;
    }
  }

  if (!resolver_ || !module_index_) {
    log.err("no resolver or module index available");
    return std::nullopt;
  }

  // Find which module contains this address
  auto module = module_index_->find_containing(address);
  if (!module) {
    log.dbg("no module found for address", redlog::field("address", address));
    return std::nullopt;
  }

  // Calculate offset within module
  uint64_t module_offset = address - module->base_address;
  log.trc(
      "resolving symbol", redlog::field("address", address), redlog::field("module_name", module->name),
      redlog::field("module_path", module->path), redlog::field("module_offset", module_offset)
  );

  // For system libraries on macOS, module->path is often just the library name
  // Try with the path first (which might just be the name)
  std::string search_path = module->path;

  log.dbg("calling LIEF resolver", redlog::field("search_path", search_path), redlog::field("offset", module_offset));

  auto symbol = resolver_->resolve_in_module(search_path, module_offset);

  if (!symbol) {
    log.dbg("no symbol found", redlog::field("path", search_path), redlog::field("offset", module_offset));

    // Return basic context with module info
    symbol_context ctx;
    ctx.module_name = module->name;
    ctx.module_offset = module_offset;

    // Cache the result
    {
      std::lock_guard<std::mutex> lock(symbol_cache_mutex_);
      if (symbol_cache_.size() >= MAX_SYMBOL_CACHE_SIZE) {
        symbol_cache_.clear();
      }
      symbol_cache_[address] = ctx;
    }

    return ctx;
  }

  log.trc(
      "symbol resolved", redlog::field("address", address), redlog::field("symbol_name", symbol->name),
      redlog::field("demangled_name", symbol->demangled_name), redlog::field("symbol_offset", symbol->offset),
      redlog::field("is_exported", symbol->is_exported)
  );

  auto result = to_context(address, *module, *symbol);

  // Cache the result
  {
    std::lock_guard<std::mutex> lock(symbol_cache_mutex_);
    // Implement simple LRU by clearing cache when it gets too large
    if (symbol_cache_.size() >= MAX_SYMBOL_CACHE_SIZE) {
      symbol_cache_.clear();
    }
    symbol_cache_[address] = result;
  }

  return result;
#else
  auto log = redlog::get_logger("w1xfer::symbol_enricher");
  log.trc("LIEF not enabled, no symbol resolution available");
  return std::nullopt;
#endif
}

std::vector<std::optional<symbol_enricher::symbol_context>> symbol_enricher::enrich_addresses(
    const std::vector<uint64_t>& addresses
) const {
#ifdef WITNESS_LIEF_ENABLED
  if (!resolver_ || !module_index_) {
    return std::vector<std::optional<symbol_context>>(addresses.size());
  }

  // Use batch resolution for efficiency
  auto symbols = resolver_->resolve_batch(addresses, *module_index_);

  std::vector<std::optional<symbol_context>> results;
  results.reserve(addresses.size());

  for (size_t i = 0; i < addresses.size(); ++i) {
    if (!symbols[i]) {
      // Try to at least get module info
      if (auto module = module_index_->find_containing(addresses[i])) {
        symbol_context ctx;
        ctx.module_name = module->name;
        ctx.module_offset = addresses[i] - module->base_address;
        results.push_back(ctx);
      } else {
        results.push_back(std::nullopt);
      }
    } else {
      // We have symbol info
      auto module = module_index_->find_containing(addresses[i]);
      if (module) {
        results.push_back(to_context(addresses[i], *module, *symbols[i]));
      } else {
        results.push_back(std::nullopt);
      }
    }
  }

  return results;
#else
  return std::vector<std::optional<symbol_context>>(addresses.size());
#endif
}

void symbol_enricher::clear_cache() {
#ifdef WITNESS_LIEF_ENABLED
  if (resolver_) {
    resolver_->clear_cache();
  }
  std::lock_guard<std::mutex> lock(symbol_cache_mutex_);
  symbol_cache_.clear();
#endif
}

symbol_enricher::cache_stats symbol_enricher::get_cache_stats() const {
  cache_stats stats{};

#ifdef WITNESS_LIEF_ENABLED
  if (resolver_) {
    auto resolver_stats = resolver_->get_cache_stats();
    stats.binary_cache_size = resolver_stats.size;
    stats.binary_cache_hits = resolver_stats.hits;
    stats.binary_cache_misses = resolver_stats.misses;
    stats.hit_rate = resolver_stats.hit_rate;
  }
#endif

  return stats;
}

symbol_enricher::symbol_context symbol_enricher::to_context(
    uint64_t address, const w1::util::module_info& module, const w1::lief::symbol_info& symbol
) const {

  symbol_context ctx;
  ctx.module_name = module.name;
  ctx.symbol_name = symbol.name;
  ctx.demangled_name = symbol.demangled_name;
  ctx.module_offset = address - module.base_address;
  // Calculate offset within the symbol
  // If the symbol has size info, we can calculate the offset
  // For MachO, symbol.offset is already module-relative
  if (symbol.size > 0 && ctx.module_offset >= symbol.offset) {
    ctx.symbol_offset = ctx.module_offset - symbol.offset;
  } else {
    // For symbols without size or when module_offset < symbol.offset,
    // just use 0 to indicate we're at the symbol start
    ctx.symbol_offset = 0;
  }
  ctx.is_exported = symbol.is_exported;
  ctx.is_imported = symbol.is_imported;

  return ctx;
}

} // namespace w1xfer