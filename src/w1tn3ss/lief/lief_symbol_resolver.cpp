#include "lief_symbol_resolver.hpp"
#include <redlog.hpp>
#include <sstream>
#include <iomanip>

// windows system resolver moved to unified symbol_resolver

namespace w1::lief {

#ifdef WITNESS_LIEF_ENABLED

// lief_binary_cache implementation
lief_binary_cache::lief_binary_cache(size_t max_size)
    : max_size_(max_size), hits_(0), misses_(0), negative_hits_(0), log_("w1.lief_binary_cache") {
#ifdef __APPLE__
  dyld_resolver_ = std::make_shared<macos_dyld_resolver>();
#endif
}

lief_binary_cache::~lief_binary_cache() = default;

LIEF::Binary* lief_binary_cache::get_or_load(const std::string& path) const {
  std::shared_lock read_lock(mutex_);

  // check negative cache first (failed paths)
  if (failed_paths_.find(path) != failed_paths_.end()) {
    negative_hits_.fetch_add(1, std::memory_order_relaxed);
    log_.dbg("negative cache hit - path previously failed", redlog::field("path", path));
    return nullptr;
  }

  // check cache
  auto it = cache_.find(path);
  if (it != cache_.end()) {
    // found in cache - need write lock to update lru
    read_lock.unlock();
    std::unique_lock write_lock(mutex_);

    // double-check after acquiring write lock
    it = cache_.find(path);
    if (it != cache_.end()) {
      // move to front (most recently used)
      lru_list_.splice(lru_list_.begin(), lru_list_, it->second.first);
      hits_.fetch_add(1, std::memory_order_relaxed);
      log_.dbg("binary cache hit", redlog::field("path", path));
      return it->second.second.get();
    }
    // if not found after write lock, continue to load
    write_lock.unlock();
    read_lock.lock();
  }

  read_lock.unlock();
  std::unique_lock write_lock(mutex_);

  // double-check
  it = cache_.find(path);
  if (it != cache_.end()) {
    lru_list_.splice(lru_list_.begin(), lru_list_, it->second.first);
    hits_.fetch_add(1, std::memory_order_relaxed);
    log_.dbg("binary cache hit after write lock", redlog::field("path", path));
    return it->second.second.get();
  }

  misses_.fetch_add(1, std::memory_order_relaxed);
  log_.dbg(
      "binary cache miss - loading binary", redlog::field("path", path), redlog::field("cache_size", cache_.size())
  );

  // load binary

  try {
    log_.trc("attempting to load binary", redlog::field("path", path));

    log_.ped("calling LIEF::Parser::parse", redlog::field("path", path));
    auto binary = LIEF::Parser::parse(path);
    if (!binary) {
      log_.ped("LIEF::Parser::parse returned null", redlog::field("path", path));
      log_.trc("failed to parse binary at original path", redlog::field("path", path));

#ifdef __APPLE__
      // try dyld shared cache dump resolution
      if (dyld_resolver_ && dyld_resolver_->is_available()) {
        log_.trc("trying dyld shared cache dump resolution");

        if (auto resolved_path = dyld_resolver_->resolve_extracted_path(path)) {
          log_.trc(
              "resolved to dyld dump path", redlog::field("original", path), redlog::field("resolved", *resolved_path)
          );

          log_.ped("calling LIEF::Parser::parse on resolved path", redlog::field("resolved_path", *resolved_path));
          binary = LIEF::Parser::parse(*resolved_path);
          if (binary) {
            log_.ped("LIEF::Parser::parse succeeded on resolved path", redlog::field("resolved_path", *resolved_path));
            // get symbol count for logging
            size_t symbol_count = 0;
            if (auto macho = dynamic_cast<LIEF::MachO::Binary*>(binary.get())) {
              symbol_count = macho->symbols().size();
            }

            log_.info(
                "loaded from dyld shared cache dump", redlog::field("library", path),
                redlog::field("symbols", symbol_count), redlog::field("dump_path", *resolved_path)
            );
          }
        }
      }
#endif

      // windows system library resolution removed - now handled by unified symbol_resolver

      if (!binary) {
        log_.trc("binary load failed completely", redlog::field("path", path));
        // add to negative cache
        failed_paths_.insert(path);
        return nullptr;
      }
    } else {
      log_.trc("loaded binary from original path", redlog::field("path", path));
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

    log_.dbg("binary cached successfully", redlog::field("path", path), redlog::field("cache_size", cache_.size()));
    return ptr;

  } catch (const std::exception& e) {
    log_.err("failed to parse binary", redlog::field("path", path), redlog::field("error", e.what()));
    // Add to negative cache
    failed_paths_.insert(path);
    return nullptr;
  }
}

void lief_binary_cache::clear() {
  std::unique_lock lock(mutex_);
  cache_.clear();
  lru_list_.clear();
  failed_paths_.clear();
  hits_ = 0;
  misses_ = 0;
  negative_hits_ = 0;
}

lief_symbol_resolver::cache_stats lief_binary_cache::get_stats() const {
  std::shared_lock lock(mutex_);
  size_t h = hits_.load();
  size_t m = misses_.load();
  size_t nh = negative_hits_.load();
  size_t total = h + m;

  return {cache_.size(), h + nh, m - nh, total > 0 ? double(h + nh) / double(total) : 0.0};
}

// lief_symbol_resolver implementation
lief_symbol_resolver::lief_symbol_resolver(const config& cfg)
    : config_(cfg), binary_cache_(std::make_unique<lief_binary_cache>(cfg.max_cache_size)),
      log_("w1.lief_symbol_resolver") {}

lief_symbol_resolver::~lief_symbol_resolver() = default;

std::optional<symbol_info> lief_symbol_resolver::resolve(
    uint64_t address, const util::module_range_index& module_index
) const {

  // lief-based resolution for all platforms
  // find which module contains this address
  auto module = module_index.find_containing(address);
  if (!module) {
    return std::nullopt;
  }

  uint64_t offset = address - module->base_address;
  return resolve_in_module(module->path, offset);
}

std::vector<std::optional<symbol_info>> lief_symbol_resolver::resolve_batch(
    const std::vector<uint64_t>& addresses, const util::module_range_index& module_index
) const {

  std::vector<std::optional<symbol_info>> results;
  results.reserve(addresses.size());

  // Group addresses by module for efficiency
  std::unordered_map<std::string, std::vector<std::pair<size_t, uint64_t>>> by_module;

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
    const std::string& module_path, uint64_t offset
) const {

  log_.trc("resolve_in_module", redlog::field("module", module_path), redlog::field("offset", offset));

  auto* binary = binary_cache_->get_or_load(module_path);
  if (!binary) {
    log_.trc("failed to load binary", redlog::field("module", module_path));
    return std::nullopt;
  }

  log_.dbg("loaded binary, checking type", redlog::field("module", module_path));

  // Platform-specific resolution
  if (auto elf = dynamic_cast<LIEF::ELF::Binary*>(binary)) {
    log_.trc("resolving ELF symbol", redlog::field("module", module_path));
    return resolve_elf_symbol(elf, offset);
  }
#ifdef _WIN32
  else if (auto pe = dynamic_cast<LIEF::PE::Binary*>(binary)) {
    log_.trc("resolving PE symbol", redlog::field("module", module_path));
    return resolve_pe_symbol(pe, offset);
  }
#endif
  else if (auto macho = dynamic_cast<LIEF::MachO::Binary*>(binary)) {
    log_.dbg("resolving MachO symbol", redlog::field("module", module_path));
    return resolve_macho_symbol(macho, offset);
  } else if (auto fat = dynamic_cast<LIEF::MachO::FatBinary*>(binary)) {
    log_.trc("handling fat binary", redlog::field("module", module_path));
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
  if (!binary) {
    return {};
  }

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

void lief_symbol_resolver::clear_cache() { binary_cache_->clear(); }

lief_symbol_resolver::cache_stats lief_symbol_resolver::get_cache_stats() const { return binary_cache_->get_stats(); }

// Platform-specific implementations
std::optional<symbol_info> lief_symbol_resolver::resolve_elf_symbol(LIEF::ELF::Binary* elf, uint64_t offset) const {

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

std::optional<symbol_info> lief_symbol_resolver::resolve_pe_symbol(LIEF::PE::Binary* pe, uint64_t offset) const {
  log_.ped("entering PE symbol resolution", redlog::field("offset", "0x%llx", offset));

  // Get PE image base for comprehensive diagnostics
  uint64_t image_base = pe->optional_header().imagebase();
  log_.ped("PE image base", redlog::field("image_base", "0x%llx", image_base));

  // Log section information to understand where our offset falls
  log_.ped("PE sections analysis", redlog::field("target_offset", "0x%llx", offset));
  for (const auto& section : pe->sections()) {
    uint64_t section_rva = section.virtual_address();
    uint64_t section_size = section.virtual_size();
    log_.ped(
        "PE section", redlog::field("name", section.name()), redlog::field("rva", "0x%llx", section_rva),
        redlog::field("size", "0x%llx", section_size), redlog::field("end_rva", "0x%llx", section_rva + section_size)
    );

    if (offset >= section_rva && offset < section_rva + section_size) {
      log_.ped(
          "target offset falls in section", redlog::field("section", section.name()),
          redlog::field("offset_in_section", "0x%llx", offset - section_rva)
      );
    }
  }

  // Check exports for EXACT matches only
  if (pe->has_exports()) {
    log_.ped(
        "PE has exports, searching for exact symbol match at offset", redlog::field("offset", "0x%llx", offset),
        redlog::field("export_count", pe->get_export()->entries().size())
    );

    for (const auto& exp : pe->get_export()->entries()) {
      log_.ped(
          "examining PE export", redlog::field("name", exp.name()), redlog::field("rva", "0x%llx", exp.address()),
          redlog::field("target_offset", "0x%llx", offset)
      );

      // EXACT RVA match - exp.address() is relative to image base
      // The offset we receive is relative to the actual load address
      // So we compare RVA directly with our offset
      if (exp.address() == offset) {
        log_.ped(
            "found exact PE export match", redlog::field("name", exp.name()),
            redlog::field("rva", "0x%llx", exp.address()), redlog::field("offset", "0x%llx", offset)
        );
        return pe_export_to_info(exp);
      }
    }

    log_.ped("no exact PE export match found", redlog::field("offset", "0x%llx", offset));
  } else {
    log_.ped("PE has no exports");
  }

  // Check imports to see if we're hitting an import thunk
  if (pe->has_imports()) {
    log_.ped("PE has imports, checking import thunks", redlog::field("import_count", pe->imports().size()));

    for (const auto& import : pe->imports()) {
      log_.ped("checking import library", redlog::field("library", import.name()));

      for (const auto& entry : import.entries()) {
        // Log detailed import entry information
        log_.ped(
            "examining import entry", redlog::field("library", import.name()), redlog::field("function", entry.name()),
            redlog::field("iat_address", "0x%llx", entry.iat_address()),
            redlog::field("iat_value", "0x%llx", entry.iat_value()), redlog::field("hint", entry.hint()),
            redlog::field("is_ordinal", entry.is_ordinal())
        );

        // Check multiple possible matches:
        // 1. IAT address (RVA of the IAT slot)
        // 2. IAT value (what the IAT slot points to - but this might be 0 in on-disk binary)
        if (entry.iat_address() == offset) {
          log_.ped(
              "found exact import IAT address match", redlog::field("library", import.name()),
              redlog::field("function", entry.name()), redlog::field("iat_address", "0x%llx", entry.iat_address())
          );

          // Create symbol info for import
          symbol_info info;
          info.name = entry.name();
          info.demangled_name = entry.name();
          info.offset = entry.iat_address();
          info.size = 0;
          info.symbol_type = symbol_info::FUNCTION;
          info.symbol_binding = symbol_info::GLOBAL;
          info.is_exported = false;
          info.is_imported = true;

          return info;
        }

        // Also check if we're hitting the resolved import address
        if (entry.iat_value() != 0 && entry.iat_value() == offset) {
          log_.ped(
              "found exact import IAT value match", redlog::field("library", import.name()),
              redlog::field("function", entry.name()), redlog::field("iat_value", "0x%llx", entry.iat_value())
          );

          // Create symbol info for import
          symbol_info info;
          info.name = entry.name();
          info.demangled_name = entry.name();
          info.offset = entry.iat_value();
          info.size = 0;
          info.symbol_type = symbol_info::FUNCTION;
          info.symbol_binding = symbol_info::GLOBAL;
          info.is_exported = false;
          info.is_imported = true;

          return info;
        }
      }
    }

    log_.ped("no exact import thunk match found", redlog::field("offset", "0x%llx", offset));
  } else {
    log_.ped("PE has no imports");
  }

  log_.ped("PE symbol resolution failed completely", redlog::field("offset", "0x%llx", offset));
  return std::nullopt;
}

std::optional<symbol_info> lief_symbol_resolver::resolve_macho_symbol(
    LIEF::MachO::Binary* macho, uint64_t offset
) const {
  std::stringstream offset_hex;
  offset_hex << "0x" << std::hex << offset;

  log_.trc(
      "resolving macho symbol", redlog::field("offset", offset), redlog::field("offset_hex", offset_hex.str()),
      redlog::field("total_symbols", macho->symbols().size())
  );

  // Get the TEXT segment's virtual address
  uint64_t text_va = 0;
  for (const auto& segment : macho->segments()) {
    if (segment.name() == "__TEXT") {
      text_va = segment.virtual_address();
      std::stringstream text_va_hex;
      text_va_hex << "0x" << std::hex << text_va;
      log_.dbg("found TEXT segment", redlog::field("virtual_address", text_va_hex.str()));
      break;
    }
  }

  // MachO symbols from dyld shared cache have absolute addresses
  // We need to convert our offset to an absolute address
  uint64_t target_address = text_va + offset;
  std::stringstream target_hex;
  target_hex << "0x" << std::hex << target_address;
  log_.dbg("looking for address", redlog::field("target_address", target_hex.str()));

  // Check all symbols for EXACT matches only
  log_.ped("searching macho symbols for exact match", redlog::field("target_address", "0x%llx", target_address));

  for (const auto& symbol : macho->symbols()) {
    // Skip unnamed symbols
    if (symbol.name().empty()) {
      continue;
    }

    log_.ped(
        "examining macho symbol", redlog::field("name", symbol.name()),
        redlog::field("value", "0x%llx", symbol.value()), redlog::field("size", symbol.size())
    );

    // Skip absolute symbols (not in memory)
    if (symbol.type() == LIEF::MachO::Symbol::TYPE::ABSOLUTE_SYM) {
      log_.ped("skipping absolute symbol", redlog::field("name", symbol.name()));
      continue;
    }

    // Skip undefined/imported symbols - they don't have real addresses
    if (symbol.category() == LIEF::MachO::Symbol::CATEGORY::UNDEFINED) {
      log_.ped("skipping undefined symbol", redlog::field("name", symbol.name()));
      continue;
    }

    uint64_t sym_addr = symbol.value();

    // EXACT range matching only
    if (symbol.size() > 0) {
      // Symbol has size - check if target is within range
      if (sym_addr <= target_address && target_address < sym_addr + symbol.size()) {
        log_.ped(
            "found exact macho symbol match with size", redlog::field("name", symbol.name()),
            redlog::field("sym_addr", "0x%llx", sym_addr), redlog::field("target", "0x%llx", target_address),
            redlog::field("size", symbol.size())
        );

        auto symbol_info = macho_symbol_to_info(symbol);
        symbol_info.offset = symbol.value() - text_va;

        log_.dbg(
            "adjusted symbol offset for module-relative addressing",
            redlog::field("absolute_address", "0x%llx", symbol.value()), redlog::field("text_va", "0x%llx", text_va),
            redlog::field("module_relative_offset", "0x%llx", symbol_info.offset)
        );

        return symbol_info;
      }
    } else {
      // Symbol has no size - only exact address match
      if (sym_addr == target_address) {
        log_.ped(
            "found exact macho symbol match (no size)", redlog::field("name", symbol.name()),
            redlog::field("sym_addr", "0x%llx", sym_addr), redlog::field("target", "0x%llx", target_address)
        );

        auto symbol_info = macho_symbol_to_info(symbol);
        symbol_info.offset = symbol.value() - text_va;

        log_.dbg(
            "adjusted symbol offset for module-relative addressing",
            redlog::field("absolute_address", "0x%llx", symbol.value()), redlog::field("text_va", "0x%llx", text_va),
            redlog::field("module_relative_offset", "0x%llx", symbol_info.offset)
        );

        return symbol_info;
      }
    }
  }

  log_.ped("no exact macho symbol match found", redlog::field("target_address", "0x%llx", target_address));
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
  info.size = 0;                            // PE exports don't have size info
  info.symbol_type = symbol_info::FUNCTION; // Assume function
  info.symbol_binding = symbol_info::GLOBAL;
  info.is_exported = true;
  info.is_imported = false;

  return info;
}

symbol_info lief_symbol_resolver::macho_symbol_to_info(const LIEF::MachO::Symbol& sym) const {

  symbol_info info;
  info.name = sym.name();
  info.demangled_name = sym.demangled_name();
  info.offset = sym.value();
  info.size = sym.size(); // Often 0 for MachO

  log_.dbg(
      "converting macho symbol to info", redlog::field("name", info.name),
      redlog::field("demangled", info.demangled_name), redlog::field("offset", "0x%llx", info.offset),
      redlog::field("size", info.size), redlog::field("type", static_cast<int>(sym.type())),
      redlog::field("category", static_cast<int>(sym.category()))
  );

  // Determine symbol type based on MachO type
  switch (sym.type()) {
  case LIEF::MachO::Symbol::TYPE::UNDEFINED:
  case LIEF::MachO::Symbol::TYPE::ABSOLUTE_SYM:
  case LIEF::MachO::Symbol::TYPE::SECTION:
  case LIEF::MachO::Symbol::TYPE::PREBOUND:
  case LIEF::MachO::Symbol::TYPE::INDIRECT:
    info.symbol_type = symbol_info::FUNCTION; // Assume function by default
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
  info.is_imported = (sym.has_binding_info() || sym.category() == LIEF::MachO::Symbol::CATEGORY::UNDEFINED);

  log_.dbg(
      "symbol info created", redlog::field("is_exported", info.is_exported),
      redlog::field("is_imported", info.is_imported), redlog::field("binding", static_cast<int>(info.symbol_binding))
  );

  return info;
}

#endif // WITNESS_LIEF_ENABLED

} // namespace w1::lief