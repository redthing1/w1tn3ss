#pragma once

#include <memory>
#include <string>
#include <optional>
#include <w1tn3ss/lief/lief_symbol_resolver.hpp>
#include <w1tn3ss/util/module_range_index.hpp>

namespace w1xfer {

// Enriches transfer entries with symbol information
class symbol_enricher {
public:
    struct symbol_context {
        std::string module_name;
        std::string symbol_name;
        std::string demangled_name;
        uint64_t symbol_offset;      // Offset within the symbol
        uint64_t module_offset;      // Offset within the module
        bool is_exported = false;
        bool is_imported = false;
    };
    
    symbol_enricher();
    ~symbol_enricher();
    
    // Initialize with module index
    void initialize(const w1::util::module_range_index& module_index);
    
    // Get enriched symbol information for an address
    std::optional<symbol_context> enrich_address(uint64_t address) const;
    
    // Batch enrichment for performance
    std::vector<std::optional<symbol_context>> enrich_addresses(
        const std::vector<uint64_t>& addresses) const;
    
    // Clear symbol cache
    void clear_cache();
    
    // Get cache statistics
    struct cache_stats {
        size_t binary_cache_size;
        size_t binary_cache_hits;
        size_t binary_cache_misses;
        double hit_rate;
    };
    
    cache_stats get_cache_stats() const;
    
private:
    std::unique_ptr<w1::lief::lief_symbol_resolver> resolver_;
    const w1::util::module_range_index* module_index_ = nullptr;
    
    // Convert internal symbol info to enriched context
    symbol_context to_context(
        uint64_t address,
        const w1::util::module_info& module,
        const w1::lief::symbol_info& symbol) const;
};

} // namespace w1xfer