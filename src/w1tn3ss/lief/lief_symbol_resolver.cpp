#include "lief_symbol_resolver.hpp"
#include <redlog.hpp>
#include <sstream>
#include <iomanip>

namespace w1::lief {

#ifdef WITNESS_LIEF_ENABLED

// lief_binary_cache implementation
lief_binary_cache::lief_binary_cache(size_t max_size) 
    : max_size_(max_size), hits_(0), misses_(0) {
#ifdef __APPLE__
    dyld_resolver_ = std::make_shared<macos_dyld_resolver>();
#endif
}

lief_binary_cache::~lief_binary_cache() = default;

LIEF::Binary* lief_binary_cache::get_or_load(const std::string& path) const {
    std::shared_lock read_lock(mutex_);
    
    // Check cache
    auto it = cache_.find(path);
    if (it != cache_.end()) {
        // Found in cache - need write lock to update LRU
        read_lock.unlock();
        std::unique_lock write_lock(mutex_);
        
        // Double-check after acquiring write lock
        it = cache_.find(path);
        if (it != cache_.end()) {
            // Move to front (most recently used)
            lru_list_.splice(lru_list_.begin(), lru_list_, it->second.first);
            hits_.fetch_add(1, std::memory_order_relaxed);
            return it->second.second.get();
        }
        // If not found after write lock, continue to load
        write_lock.unlock();
        read_lock.lock();
    }
    
    read_lock.unlock();
    std::unique_lock write_lock(mutex_);
    
    // Double-check
    it = cache_.find(path);
    if (it != cache_.end()) {
        lru_list_.splice(lru_list_.begin(), lru_list_, it->second.first);
        hits_.fetch_add(1, std::memory_order_relaxed);
        return it->second.second.get();
    }
    
    misses_.fetch_add(1, std::memory_order_relaxed);
    
    // Load binary
    auto log = redlog::get_logger("w1::lief::binary_cache");
    
    try {
        log.dbg("attempting to load binary", redlog::field("path", path));
        
        auto binary = LIEF::Parser::parse(path);
        if (!binary) {
            log.dbg("failed to parse binary at original path", redlog::field("path", path));
            
#ifdef __APPLE__
            // Try dyld shared cache dump resolution
            if (dyld_resolver_ && dyld_resolver_->is_available()) {
                log.dbg("trying dyld shared cache dump resolution");
                
                if (auto resolved_path = dyld_resolver_->resolve_extracted_path(path)) {
                    log.dbg("resolved to dyld dump path", 
                             redlog::field("original", path),
                             redlog::field("resolved", *resolved_path));
                    
                    binary = LIEF::Parser::parse(*resolved_path);
                    if (binary) {
                        // Get symbol count for logging
                        size_t symbol_count = 0;
                        if (auto macho = dynamic_cast<LIEF::MachO::Binary*>(binary.get())) {
                            symbol_count = macho->symbols().size();
                        }
                        
                        log.info("loaded from dyld shared cache dump",
                                redlog::field("library", path),
                                redlog::field("symbols", symbol_count),
                                redlog::field("dump_path", *resolved_path));
                    }
                }
            }
#endif
            
            if (!binary) {
                log.dbg("binary load failed completely", redlog::field("path", path));
                return nullptr;
            }
        } else {
            log.dbg("loaded binary from original path", redlog::field("path", path));
        }
        
        // Evict if needed
        if (cache_.size() >= max_size_) {
            auto last = lru_list_.back();
            cache_.erase(last);
            lru_list_.pop_back();
        }
        
        // Add to cache
        lru_list_.push_front(path);
        auto* ptr = binary.get();
        cache_[path] = {lru_list_.begin(), std::move(binary)};
        
        return ptr;
        
    } catch (const std::exception& e) {
        log.err("failed to parse binary", redlog::field("path", path), redlog::field("error", e.what()));
        return nullptr;
    }
}

void lief_binary_cache::clear() {
    std::unique_lock lock(mutex_);
    cache_.clear();
    lru_list_.clear();
    hits_ = 0;
    misses_ = 0;
}

lief_symbol_resolver::cache_stats lief_binary_cache::get_stats() const {
    std::shared_lock lock(mutex_);
    size_t h = hits_.load();
    size_t m = misses_.load();
    size_t total = h + m;
    
    return {
        cache_.size(),
        h,
        m,
        total > 0 ? double(h) / double(total) : 0.0
    };
}

// lief_symbol_resolver implementation
lief_symbol_resolver::lief_symbol_resolver(const config& cfg)
    : config_(cfg), binary_cache_(std::make_unique<lief_binary_cache>(cfg.max_cache_size)) {}

lief_symbol_resolver::~lief_symbol_resolver() = default;

std::optional<symbol_info> lief_symbol_resolver::resolve(
    uint64_t address,
    const util::module_range_index& module_index) const {
    
    // Find which module contains this address
    auto module = module_index.find_containing(address);
    if (!module) return std::nullopt;
    
    uint64_t offset = address - module->base_address;
    return resolve_in_module(module->path, offset);
}

std::vector<std::optional<symbol_info>> lief_symbol_resolver::resolve_batch(
    const std::vector<uint64_t>& addresses,
    const util::module_range_index& module_index) const {
    
    std::vector<std::optional<symbol_info>> results;
    results.reserve(addresses.size());
    
    // Group addresses by module for efficiency
    std::unordered_map<std::string, 
                      std::vector<std::pair<size_t, uint64_t>>> by_module;
    
    for (size_t i = 0; i < addresses.size(); ++i) {
        if (auto mod = module_index.find_containing(addresses[i])) {
            by_module[mod->path].emplace_back(i, addresses[i] - mod->base_address);
        }
    }
    
    // Resolve per module
    results.resize(addresses.size());
    for (const auto& [module_path, queries] : by_module) {
        for (const auto& [index, offset] : queries) {
            results[index] = resolve_in_module(module_path, offset);
        }
    }
    
    return results;
}

std::optional<symbol_info> lief_symbol_resolver::resolve_in_module(
    const std::string& module_path,
    uint64_t offset) const {
    
    auto log = redlog::get_logger("w1::lief::symbol_resolver");
    log.ped("resolve_in_module", 
             redlog::field("module", module_path),
             redlog::field("offset", offset));
    
    auto* binary = binary_cache_->get_or_load(module_path);
    if (!binary) {
        log.dbg("failed to load binary", redlog::field("module", module_path));
        return std::nullopt;
    }
    
    log.ped("loaded binary, checking type", redlog::field("module", module_path));
    
    // Platform-specific resolution
    if (auto elf = dynamic_cast<LIEF::ELF::Binary*>(binary)) {
        log.ped("resolving ELF symbol", redlog::field("module", module_path));
        return resolve_elf_symbol(elf, offset);
    }
    #ifdef _WIN32
    else if (auto pe = dynamic_cast<LIEF::PE::Binary*>(binary)) {
        log.ped("resolving PE symbol", redlog::field("module", module_path));
        return resolve_pe_symbol(pe, offset);
    }
    #endif
    else if (auto macho = dynamic_cast<LIEF::MachO::Binary*>(binary)) {
        log.ped("resolving MachO symbol", redlog::field("module", module_path));
        return resolve_macho_symbol(macho, offset);
    }
    else if (auto fat = dynamic_cast<LIEF::MachO::FatBinary*>(binary)) {
        log.ped("handling fat binary", redlog::field("module", module_path));
        // Handle fat binaries by selecting the appropriate architecture
        // For now, just use the first one - in production code you'd want
        // to select based on the current process architecture
        if (fat->size() > 0) {
            auto* binary = fat->at(0);
            return resolve_macho_symbol(binary, offset);
        }
    }
    
    return std::nullopt;
}

std::vector<symbol_info> lief_symbol_resolver::get_all_symbols(const std::string& module_path) const {
    auto* binary = binary_cache_->get_or_load(module_path);
    if (!binary) return {};
    
    std::vector<symbol_info> symbols;
    
    if (auto elf = dynamic_cast<LIEF::ELF::Binary*>(binary)) {
        // Process dynamic symbols (most important for API calls)
        for (const auto& sym : elf->dynamic_symbols()) {
            if (!sym.name().empty()) {
                symbols.push_back(elf_symbol_to_info(sym));
            }
        }
        // Also process static symbols if needed
        if (config_.resolve_imports) {
            for (const auto& sym : elf->symbols()) {
                if (!sym.name().empty()) {
                    symbols.push_back(elf_symbol_to_info(sym));
                }
            }
        }
    }
    // ... similar for PE and MachO ...
    
    return symbols;
}

void lief_symbol_resolver::clear_cache() {
    binary_cache_->clear();
}

lief_symbol_resolver::cache_stats lief_symbol_resolver::get_cache_stats() const {
    return binary_cache_->get_stats();
}

// Platform-specific implementations
std::optional<symbol_info> lief_symbol_resolver::resolve_elf_symbol(
    LIEF::ELF::Binary* elf, uint64_t offset) const {
    
    // Try dynamic symbols first (more likely for API calls)
    for (const auto& sym : elf->dynamic_symbols()) {
        if (sym.value() <= offset && offset < sym.value() + sym.size() && !sym.name().empty()) {
            return elf_symbol_to_info(sym);
        }
    }
    
    // Try static symbols
    for (const auto& sym : elf->symbols()) {
        if (sym.value() <= offset && offset < sym.value() + sym.size() && !sym.name().empty()) {
            return elf_symbol_to_info(sym);
        }
    }
    
    return std::nullopt;
}

std::optional<symbol_info> lief_symbol_resolver::resolve_pe_symbol(
    LIEF::PE::Binary* pe, uint64_t offset) const {
    
    // Check exports
    if (pe->has_exports()) {
        // PE exports don't have size info, but we can find the closest match
        const LIEF::PE::ExportEntry* best_match = nullptr;
        uint64_t best_distance = UINT64_MAX;
        
        if (pe->has_exports()) {
            for (const auto& exp : pe->get_export()->entries()) {
                if (exp.address() <= offset) {
                    uint64_t distance = offset - exp.address();
                    if (distance < best_distance) {
                        best_distance = distance;
                        best_match = &exp;
                    }
                }
            }
        }
        
        if (best_match && best_distance < 0x1000) {  // Within 4KB is reasonable
            return pe_export_to_info(*best_match);
        }
    }
    
    return std::nullopt;
}

std::optional<symbol_info> lief_symbol_resolver::resolve_macho_symbol(
    LIEF::MachO::Binary* macho, uint64_t offset) const {
    
    auto log = redlog::get_logger("w1::lief::symbol_resolver");
    std::stringstream offset_hex;
    offset_hex << "0x" << std::hex << offset;
    
    log.ped("resolving macho symbol", 
             redlog::field("offset", offset),
             redlog::field("offset_hex", offset_hex.str()),
             redlog::field("total_symbols", macho->symbols().size()));
    
    // Get the TEXT segment's virtual address
    uint64_t text_va = 0;
    for (const auto& segment : macho->segments()) {
        if (segment.name() == "__TEXT") {
            text_va = segment.virtual_address();
            std::stringstream text_va_hex;
            text_va_hex << "0x" << std::hex << text_va;
            log.ped("found TEXT segment",
                     redlog::field("virtual_address", text_va_hex.str()));
            break;
        }
    }
    
    // MachO symbols from dyld shared cache have absolute addresses
    // We need to convert our offset to an absolute address
    uint64_t target_address = text_va + offset;
    std::stringstream target_hex;
    target_hex << "0x" << std::hex << target_address;
    log.ped("looking for address",
             redlog::field("target_address", target_hex.str()));
    
    // MachO symbols often don't have size information, so we need to find
    // the best matching symbol by checking all symbols
    const LIEF::MachO::Symbol* best_match = nullptr;
    uint64_t best_distance = UINT64_MAX;
    
    // Log first few symbols for debugging
    int symbol_count = 0;
    
    // Check all symbols (includes both exported and imported)
    for (const auto& symbol : macho->symbols()) {
        // Skip unnamed symbols
        if (symbol.name().empty()) {
            continue;
        }
        
        uint64_t sym_addr = symbol.value();
        
        // Log first few symbols for debugging
        if (symbol_count++ < 5 || symbol.name() == "_strstr" || symbol.name() == "_strlen" || symbol.name() == "_strcpy") {
            std::stringstream sym_hex;
            sym_hex << "0x" << std::hex << sym_addr;
            log.ped("examining symbol",
                     redlog::field("name", symbol.name()),
                     redlog::field("value", sym_addr),
                     redlog::field("value_hex", sym_hex.str()),
                     redlog::field("type", static_cast<int>(symbol.type())),
                     redlog::field("category", static_cast<int>(symbol.category())));
        }
        
        // Skip absolute symbols (not in memory)
        if (symbol.type() == LIEF::MachO::Symbol::TYPE::ABSOLUTE_SYM) {
            continue;
        }
        
        // Skip undefined/imported symbols - they don't have real addresses
        if (symbol.category() == LIEF::MachO::Symbol::CATEGORY::UNDEFINED) {
            continue;
        }
        
        // Check if this symbol could contain our target address
        if (sym_addr <= target_address) {
            uint64_t distance = target_address - sym_addr;
            
            // Log potential matches
            if (distance < 0x1000) {  // Within 4KB
                log.ped("potential match",
                         redlog::field("name", symbol.name()),
                         redlog::field("value", sym_addr),
                         redlog::field("distance", distance),
                         redlog::field("size", symbol.size()));
            }
            
            // If symbol has size, check if offset is within bounds
            if (symbol.size() > 0 && distance >= symbol.size()) {
                continue;
            }
            
            // Keep track of closest symbol
            if (distance < best_distance) {
                best_distance = distance;
                best_match = &symbol;
            }
        }
    }
    
    // If we found a match within reasonable distance
    if (best_match && best_distance < 0x10000) {  // 64KB is reasonable for MachO
        std::stringstream value_hex, offset_hex2;
        value_hex << "0x" << std::hex << best_match->value();
        offset_hex2 << "0x" << std::hex << offset;
        
        log.dbg("found macho symbol", 
                redlog::field("name", best_match->name()),
                redlog::field("value", best_match->value()),
                redlog::field("value_hex", value_hex.str()),
                redlog::field("distance", best_distance),
                redlog::field("offset", offset),
                redlog::field("offset_hex", offset_hex2.str()),
                redlog::field("size", best_match->size()),
                redlog::field("is_exported", best_match->has_export_info()),
                redlog::field("is_imported", best_match->category() == LIEF::MachO::Symbol::CATEGORY::UNDEFINED));
        
        auto symbol_info = macho_symbol_to_info(*best_match);
        // Convert absolute address to module-relative offset for dyld shared cache symbols
        // This ensures symbol_enricher can correctly calculate symbol_offset
        symbol_info.offset = best_match->value() - text_va;
        
        log.ped("adjusted symbol offset for module-relative addressing",
                 redlog::field("absolute_address", best_match->value()),
                 redlog::field("text_va", text_va),
                 redlog::field("module_relative_offset", symbol_info.offset));
        
        return symbol_info;
    }
    
    log.dbg("no macho symbol found", 
            redlog::field("offset", offset),
            redlog::field("best_distance", best_distance),
            redlog::field("best_match", best_match ? best_match->name() : "none"));
    return std::nullopt;
}

symbol_info lief_symbol_resolver::elf_symbol_to_info(const LIEF::ELF::Symbol& sym) const {
    symbol_info info;
    info.name = sym.name();
    info.demangled_name = sym.demangled_name();
    info.offset = sym.value();
    info.size = sym.size();
    
    switch (sym.type()) {
    case LIEF::ELF::Symbol::TYPE::FUNC:
        info.symbol_type = symbol_info::FUNCTION;
        break;
    case LIEF::ELF::Symbol::TYPE::OBJECT:
        info.symbol_type = symbol_info::OBJECT;
        break;
    default:
        info.symbol_type = symbol_info::UNKNOWN;
        break;
    }
    
    switch (sym.binding()) {
    case LIEF::ELF::Symbol::BINDING::LOCAL:
        info.symbol_binding = symbol_info::LOCAL;
        break;
    case LIEF::ELF::Symbol::BINDING::GLOBAL:
        info.symbol_binding = symbol_info::GLOBAL;
        break;
    case LIEF::ELF::Symbol::BINDING::WEAK:
        info.symbol_binding = symbol_info::WEAK;
        break;
    case LIEF::ELF::Symbol::BINDING::GNU_UNIQUE:
        info.symbol_binding = symbol_info::GLOBAL;
        break;
    }
    
    info.is_exported = sym.is_exported();
    info.is_imported = sym.is_imported();
    
    if (sym.has_version()) {
        const auto& ver = sym.symbol_version();
        if (ver->has_auxiliary_version()) {
            info.version = ver->symbol_version_auxiliary()->name();
        }
    }
    
    if (sym.section()) {
        info.section = sym.section()->name();
    }
    
    return info;
}

symbol_info lief_symbol_resolver::pe_export_to_info(const LIEF::PE::ExportEntry& exp) const {
    symbol_info info;
    info.name = exp.name();
    info.demangled_name = exp.name(); // PE doesn't have mangling info in exports
    info.offset = exp.address();
    info.size = 0; // PE exports don't have size info
    info.symbol_type = symbol_info::FUNCTION; // Assume function
    info.symbol_binding = symbol_info::GLOBAL;
    info.is_exported = true;
    info.is_imported = false;
    
    return info;
}

symbol_info lief_symbol_resolver::macho_symbol_to_info(const LIEF::MachO::Symbol& sym) const {
    auto log = redlog::get_logger("w1::lief::symbol_resolver");
    
    symbol_info info;
    info.name = sym.name();
    info.demangled_name = sym.demangled_name();
    info.offset = sym.value();
    info.size = sym.size();  // Often 0 for MachO
    
    log.ped("converting macho symbol to info",
             redlog::field("name", info.name),
             redlog::field("demangled", info.demangled_name),
             redlog::field("offset", info.offset),
             redlog::field("size", info.size),
             redlog::field("type", static_cast<int>(sym.type())),
             redlog::field("category", static_cast<int>(sym.category())));
    
    // Determine symbol type based on MachO type
    switch (sym.type()) {
    case LIEF::MachO::Symbol::TYPE::UNDEFINED:
    case LIEF::MachO::Symbol::TYPE::ABSOLUTE_SYM:
    case LIEF::MachO::Symbol::TYPE::SECTION:
    case LIEF::MachO::Symbol::TYPE::PREBOUND:
    case LIEF::MachO::Symbol::TYPE::INDIRECT:
        info.symbol_type = symbol_info::FUNCTION;  // Assume function by default
        break;
    }
    
    // Determine binding based on category
    switch (sym.category()) {
    case LIEF::MachO::Symbol::CATEGORY::LOCAL:
        info.symbol_binding = symbol_info::LOCAL;
        break;
    case LIEF::MachO::Symbol::CATEGORY::EXTERNAL:
        info.symbol_binding = symbol_info::GLOBAL;
        break;
    case LIEF::MachO::Symbol::CATEGORY::UNDEFINED:
        info.symbol_binding = symbol_info::WEAK;
        break;
    default:
        info.symbol_binding = symbol_info::LOCAL;
        break;
    }
    
    // Check export/import status
    info.is_exported = sym.has_export_info();
    info.is_imported = (sym.has_binding_info() || 
                       sym.category() == LIEF::MachO::Symbol::CATEGORY::UNDEFINED);
    
    log.ped("symbol info created",
             redlog::field("is_exported", info.is_exported),
             redlog::field("is_imported", info.is_imported),
             redlog::field("binding", static_cast<int>(info.symbol_binding)));
    
    return info;
}

#endif // WITNESS_LIEF_ENABLED

} // namespace w1::lief