#include "lief_symbol_backend.hpp"
#include "path_resolver.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>
#include <iomanip>

#ifdef __APPLE__
// MachO constants from mach-o/nlist.h
#define N_STAB 0xe0 /* if any of these bits set, a symbolic debugging entry */
#define N_TYPE 0x0e /* mask for the type bits */
#define N_EXT 0x01  /* external symbol bit, set for external symbols */
#endif

namespace w1::symbols {

#ifdef WITNESS_LIEF_ENABLED

// lief_binary_cache implementation
lief_binary_cache::lief_binary_cache(size_t max_size)
    : max_size_(max_size), hits_(0), misses_(0), negative_hits_(0), log_("w1.lief_binary_cache") {}

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
      log_.trc("binary load failed", redlog::field("path", path));
      // add to negative cache
      failed_paths_.insert(path);
      return nullptr;
    } else {
      log_.trc("loaded binary from path", redlog::field("path", path));
    }

    // evict if needed
    if (cache_.size() >= max_size_) {
      auto last = lru_list_.back();
      cache_.erase(last);
      lru_list_.pop_back();
    }

    // add to cache
    lru_list_.push_front(path);
    auto* ptr = binary.get();
    cache_[path] = {lru_list_.begin(), std::move(binary)};

    log_.dbg("binary cached successfully", redlog::field("path", path), redlog::field("cache_size", cache_.size()));
    return ptr;

  } catch (const std::exception& e) {
    log_.err("failed to parse binary", redlog::field("path", path), redlog::field("error", e.what()));
    // add to negative cache
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

lief_binary_cache::cache_stats lief_binary_cache::get_stats() const {
  std::shared_lock lock(mutex_);
  size_t h = hits_.load();
  size_t m = misses_.load();
  size_t nh = negative_hits_.load();
  size_t total = h + m;

  return {cache_.size(), h + nh, m - nh, total > 0 ? double(h + nh) / double(total) : 0.0};
}

// lief_symbol_backend implementation
lief_symbol_backend::lief_symbol_backend(const config& cfg)
    : config_(cfg), binary_cache_(std::make_unique<lief_binary_cache>(cfg.max_cache_size)),
      log_("w1.lief_symbol_backend") {}

lief_symbol_backend::~lief_symbol_backend() = default;

bool lief_symbol_backend::is_available() const {
  return true; // lief is available if compiled with WITNESS_LIEF_ENABLED
}

lief_symbol_backend::capabilities lief_symbol_backend::get_capabilities() const {
  return {
      .supports_runtime_resolution = false, // file-based only
      .supports_file_resolution = true,
      .supports_pattern_matching = true,
      .supports_demangling = true
  };
}

void lief_symbol_backend::set_path_resolver(std::shared_ptr<path_resolver> resolver) { path_resolver_ = resolver; }

std::optional<symbol_info> lief_symbol_backend::resolve_address(uint64_t address) const {
  // lief backend requires module context, cannot resolve raw addresses
  log_.trc(
      "lief backend cannot resolve raw addresses without module context", redlog::field("address", "0x%016llx", address)
  );
  return std::nullopt;
}

std::optional<uint64_t> lief_symbol_backend::resolve_name(
    const std::string& name, const std::string& module_hint
) const {
  if (module_hint.empty()) {
    log_.trc("lief backend requires module hint for name resolution", redlog::field("name", name));
    return std::nullopt;
  }

  // resolve module path if needed
  std::string module_path = module_hint;
  if (path_resolver_) {
    if (auto resolved = path_resolver_->resolve_library_path(module_hint)) {
      module_path = *resolved;
    }
  }

  auto* binary = binary_cache_->get_or_load(module_path);
  if (!binary) {
    log_.trc("failed to load binary", redlog::field("module", module_path));
    return std::nullopt;
  }

  // platform-specific symbol lookup
  if (auto elf = dynamic_cast<LIEF::ELF::Binary*>(binary)) {
    return find_symbol_in_elf(elf, name);
  } else if (auto pe = dynamic_cast<LIEF::PE::Binary*>(binary)) {
    return find_symbol_in_pe(pe, name);
  } else if (auto macho = dynamic_cast<LIEF::MachO::Binary*>(binary)) {
    return find_symbol_in_macho(macho, name);
  } else if (auto fat = dynamic_cast<LIEF::MachO::FatBinary*>(binary)) {
    // handle fat binaries by using first architecture
    if (fat->size() > 0) {
      return find_symbol_in_macho(fat->at(0), name);
    }
  }

  return std::nullopt;
}

std::optional<symbol_info> lief_symbol_backend::resolve_in_module(
    const std::string& module_path, uint64_t offset
) const {
  log_.trc("resolve_in_module", redlog::field("module", module_path), redlog::field("offset", "0x%016llx", offset));

  auto* binary = binary_cache_->get_or_load(module_path);
  if (!binary) {
    log_.trc("failed to load binary", redlog::field("module", module_path));
    return std::nullopt;
  }

  log_.dbg("loaded binary, checking type", redlog::field("module", module_path));

  // platform-specific resolution
  if (auto elf = dynamic_cast<LIEF::ELF::Binary*>(binary)) {
    log_.trc("resolving ELF symbol", redlog::field("module", module_path));
    return resolve_elf_symbol(elf, offset);
  } else if (auto pe = dynamic_cast<LIEF::PE::Binary*>(binary)) {
    log_.trc("resolving PE symbol", redlog::field("module", module_path));
    return resolve_pe_symbol(pe, offset);
  } else if (auto macho = dynamic_cast<LIEF::MachO::Binary*>(binary)) {
    log_.dbg("resolving MachO symbol", redlog::field("module", module_path));
    return resolve_macho_symbol(macho, offset);
  } else if (auto fat = dynamic_cast<LIEF::MachO::FatBinary*>(binary)) {
    log_.trc("handling fat binary", redlog::field("module", module_path));
    // handle fat binaries by selecting the appropriate architecture
    // for now, just use the first one
    if (fat->size() > 0) {
      auto* binary = fat->at(0);
      return resolve_macho_symbol(binary, offset);
    }
  }

  return std::nullopt;
}

std::vector<symbol_info> lief_symbol_backend::find_symbols(
    const std::string& pattern, const std::string& module_hint
) const {
  if (module_hint.empty()) {
    log_.trc("lief backend requires module hint for symbol search", redlog::field("pattern", pattern));
    return {};
  }

  // resolve module path if needed
  std::string module_path = module_hint;
  if (path_resolver_) {
    if (auto resolved = path_resolver_->resolve_library_path(module_hint)) {
      module_path = *resolved;
    }
  }

  auto* binary = binary_cache_->get_or_load(module_path);
  if (!binary) {
    return {};
  }

  // platform-specific pattern search
  if (auto elf = dynamic_cast<LIEF::ELF::Binary*>(binary)) {
    return find_symbols_in_elf(elf, pattern);
  } else if (auto pe = dynamic_cast<LIEF::PE::Binary*>(binary)) {
    return find_symbols_in_pe(pe, pattern);
  } else if (auto macho = dynamic_cast<LIEF::MachO::Binary*>(binary)) {
    return find_symbols_in_macho(macho, pattern);
  } else if (auto fat = dynamic_cast<LIEF::MachO::FatBinary*>(binary)) {
    if (fat->size() > 0) {
      return find_symbols_in_macho(fat->at(0), pattern);
    }
  }

  return {};
}

std::vector<symbol_info> lief_symbol_backend::get_module_symbols(const std::string& module_path) const {
  auto* binary = binary_cache_->get_or_load(module_path);
  if (!binary) {
    return {};
  }

  std::vector<symbol_info> symbols;

  if (auto elf = dynamic_cast<LIEF::ELF::Binary*>(binary)) {
    // process dynamic symbols (most important for API calls)
    for (const auto& sym : elf->dynamic_symbols()) {
      if (!sym.name().empty()) {
        symbols.push_back(elf_symbol_to_info(sym));
      }
    }
    // also process static symbols if needed
    if (config_.resolve_imports) {
      for (const auto& sym : elf->symbols()) {
        if (!sym.name().empty()) {
          symbols.push_back(elf_symbol_to_info(sym));
        }
      }
    }
  } else if (auto pe = dynamic_cast<LIEF::PE::Binary*>(binary)) {
    // process exports
    if (pe->has_exports()) {
      for (const auto& exp : pe->get_export()->entries()) {
        symbols.push_back(pe_export_to_info(exp));
      }
    }
  } else if (auto macho = dynamic_cast<LIEF::MachO::Binary*>(binary)) {
    for (const auto& sym : macho->symbols()) {
      if (!sym.name().empty()) {
        symbols.push_back(macho_symbol_to_info(sym));
      }
    }
  }

  return symbols;
}

void lief_symbol_backend::clear_cache() { binary_cache_->clear(); }

// platform-specific symbol resolution
std::optional<symbol_info> lief_symbol_backend::resolve_elf_symbol(LIEF::ELF::Binary* elf, uint64_t offset) const {
  // try dynamic symbols first (more likely for API calls)
  for (const auto& sym : elf->dynamic_symbols()) {
    if (sym.value() <= offset && offset < sym.value() + sym.size() && !sym.name().empty()) {
      auto info = elf_symbol_to_info(sym);
      info.module_offset = offset;
      return info;
    }
  }

  // try static symbols
  for (const auto& sym : elf->symbols()) {
    if (sym.value() <= offset && offset < sym.value() + sym.size() && !sym.name().empty()) {
      auto info = elf_symbol_to_info(sym);
      info.module_offset = offset;
      return info;
    }
  }

  return std::nullopt;
}

std::optional<symbol_info> lief_symbol_backend::resolve_pe_symbol(LIEF::PE::Binary* pe, uint64_t offset) const {
  log_.ped("entering PE symbol resolution", redlog::field("offset", "0x%016llx", offset));

  // check exports for exact matches only
  if (pe->has_exports()) {
    log_.ped(
        "PE has exports, searching for exact symbol match at offset", redlog::field("offset", "0x%016llx", offset),
        redlog::field("export_count", pe->get_export()->entries().size())
    );

    for (const auto& exp : pe->get_export()->entries()) {
      // exact RVA match
      if (exp.address() == offset) {
        log_.ped(
            "found exact PE export match", redlog::field("name", exp.name()),
            redlog::field("rva", "0x%016llx", exp.address())
        );
        auto info = pe_export_to_info(exp);
        info.module_offset = offset;
        return info;
      }
    }
  }

  return std::nullopt;
}

std::optional<symbol_info> lief_symbol_backend::resolve_macho_symbol(
    LIEF::MachO::Binary* macho, uint64_t offset
) const {
  log_.dbg(
      "resolve_macho_symbol", redlog::field("offset", "0x%016llx", offset),
      redlog::field("symbol_count", macho->symbols().size())
  );

  // macho symbols don't have size information, so we can't do range checks
  // we need to find the closest symbol that starts before our offset
  const LIEF::MachO::Symbol* best_match = nullptr;
  uint64_t best_distance = UINT64_MAX;

  for (const auto& sym : macho->symbols()) {
    // skip undefined symbols
    if (sym.type() == LIEF::MachO::Symbol::TYPE::UNDEFINED) {
      continue;
    }

    uint64_t sym_addr = sym.value();

    if (sym_addr <= offset) {
      uint64_t distance = offset - sym_addr;
      if (distance < best_distance && !sym.name().empty()) {
        best_match = &sym;
        best_distance = distance;
      }
    }
  }

  if (best_match) {
    log_.dbg(
        "found closest MachO symbol", redlog::field("name", best_match->name()),
        redlog::field("offset_from_symbol", best_distance)
    );

    auto info = macho_symbol_to_info(*best_match);
    info.offset_from_symbol = best_distance; // store displacement from symbol start
    info.module_offset = offset;
    return info;
  }

  return std::nullopt;
}

// symbol name resolution
std::optional<uint64_t> lief_symbol_backend::find_symbol_in_elf(LIEF::ELF::Binary* elf, const std::string& name) const {
  // check dynamic symbols first
  for (const auto& sym : elf->dynamic_symbols()) {
    if (sym.name() == name) {
      return sym.value();
    }
  }

  // check static symbols
  for (const auto& sym : elf->symbols()) {
    if (sym.name() == name) {
      return sym.value();
    }
  }

  return std::nullopt;
}

std::optional<uint64_t> lief_symbol_backend::find_symbol_in_pe(LIEF::PE::Binary* pe, const std::string& name) const {
  if (pe->has_exports()) {
    for (const auto& exp : pe->get_export()->entries()) {
      if (exp.name() == name) {
        return exp.address(); // RVA
      }
    }
  }

  return std::nullopt;
}

std::optional<uint64_t> lief_symbol_backend::find_symbol_in_macho(
    LIEF::MachO::Binary* macho, const std::string& name
) const {
  for (const auto& sym : macho->symbols()) {
    if (sym.name() == name && sym.type() != LIEF::MachO::Symbol::TYPE::UNDEFINED) {
      return sym.value();
    }
  }

  return std::nullopt;
}

// pattern matching
bool lief_symbol_backend::matches_pattern(const std::string& name, const std::string& pattern) const {
  if (pattern.empty()) {
    return true; // empty pattern matches all
  }

  // simple wildcard matching
  std::string name_lower = name;
  std::string pattern_lower = pattern;
  std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
  std::transform(pattern_lower.begin(), pattern_lower.end(), pattern_lower.begin(), ::tolower);

  if (pattern_lower.front() == '*' && pattern_lower.back() == '*') {
    // *substring*
    return name_lower.find(pattern_lower.substr(1, pattern_lower.length() - 2)) != std::string::npos;
  } else if (pattern_lower.back() == '*') {
    // prefix*
    return name_lower.find(pattern_lower.substr(0, pattern_lower.length() - 1)) == 0;
  } else if (pattern_lower.front() == '*') {
    // *suffix
    std::string suffix = pattern_lower.substr(1);
    return name_lower.length() >= suffix.length() &&
           name_lower.compare(name_lower.length() - suffix.length(), suffix.length(), suffix) == 0;
  } else {
    // exact match
    return name_lower == pattern_lower;
  }
}

std::vector<symbol_info> lief_symbol_backend::find_symbols_in_elf(
    LIEF::ELF::Binary* elf, const std::string& pattern
) const {
  std::vector<symbol_info> results;

  // check dynamic symbols
  for (const auto& sym : elf->dynamic_symbols()) {
    if (!sym.name().empty() && matches_pattern(sym.name(), pattern)) {
      results.push_back(elf_symbol_to_info(sym));
    }
  }

  // check static symbols if configured
  if (config_.resolve_imports) {
    for (const auto& sym : elf->symbols()) {
      if (!sym.name().empty() && matches_pattern(sym.name(), pattern)) {
        results.push_back(elf_symbol_to_info(sym));
      }
    }
  }

  return results;
}

std::vector<symbol_info> lief_symbol_backend::find_symbols_in_pe(
    LIEF::PE::Binary* pe, const std::string& pattern
) const {
  std::vector<symbol_info> results;

  if (pe->has_exports()) {
    for (const auto& exp : pe->get_export()->entries()) {
      if (matches_pattern(exp.name(), pattern)) {
        results.push_back(pe_export_to_info(exp));
      }
    }
  }

  return results;
}

std::vector<symbol_info> lief_symbol_backend::find_symbols_in_macho(
    LIEF::MachO::Binary* macho, const std::string& pattern
) const {
  std::vector<symbol_info> results;

  for (const auto& sym : macho->symbols()) {
    if (!sym.name().empty() && sym.type() != LIEF::MachO::Symbol::TYPE::UNDEFINED &&
        matches_pattern(sym.name(), pattern)) {
      results.push_back(macho_symbol_to_info(sym));
    }
  }

  return results;
}

// conversion helpers
symbol_info lief_symbol_backend::elf_symbol_to_info(const LIEF::ELF::Symbol& sym) const {
  symbol_info info;
  info.name = sym.name();
  info.demangled_name = sym.demangled_name();
  info.offset_from_symbol = 0; // will be calculated if needed
  info.module_offset = 0;      // will be set in resolve_in_module if needed
  info.size = sym.size();

  // map symbol type
  switch (sym.type()) {
  case LIEF::ELF::Symbol::TYPE::FUNC:
    info.symbol_type = symbol_info::FUNCTION;
    break;
  case LIEF::ELF::Symbol::TYPE::OBJECT:
    info.symbol_type = symbol_info::OBJECT;
    break;
  default:
    info.symbol_type = symbol_info::UNKNOWN;
  }

  // map binding
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
  default:
    info.symbol_binding = symbol_info::UNKNOWN_BINDING;
  }

  info.is_exported = sym.is_exported();
  info.is_imported = sym.is_imported();

  return info;
}

symbol_info lief_symbol_backend::pe_export_to_info(const LIEF::PE::ExportEntry& exp) const {
  symbol_info info;
  info.name = exp.name();
  info.demangled_name = exp.name(); // PE doesn't have demangling in LIEF
  info.offset_from_symbol = 0;
  info.module_offset = 0;                   // will be set in resolve_in_module if needed
  info.size = 0;                            // PE exports don't have size
  info.symbol_type = symbol_info::FUNCTION; // assume function for exports
  info.symbol_binding = symbol_info::GLOBAL;
  info.is_exported = true;
  info.is_imported = false;

  return info;
}

symbol_info lief_symbol_backend::macho_symbol_to_info(const LIEF::MachO::Symbol& sym) const {
  symbol_info info;
  info.name = sym.name();
  info.demangled_name = sym.demangled_name();
  info.offset_from_symbol = 0;
  info.module_offset = 0; // will be set in resolve_in_module if needed
  info.size = 0;          // macho symbols don't have size

  // determine type from macho type flags
  // n_stab (0xe0) and n_ext (0x01) are macho-specific constants
  // only use these on non-windows platforms where they're defined
#ifndef _WIN32
  if (sym.raw_type() & N_STAB) {
    info.symbol_type = symbol_info::DEBUG;
  } else
#endif
      if (sym.type() == LIEF::MachO::Symbol::TYPE::SECTION) {
    // could be function or data, default to function
    info.symbol_type = symbol_info::FUNCTION;
  } else {
    info.symbol_type = symbol_info::UNKNOWN;
  }

  // determine binding from external flag
#ifndef _WIN32
  if (sym.raw_type() & N_EXT) {
    info.symbol_binding = symbol_info::GLOBAL;
  } else {
    info.symbol_binding = symbol_info::LOCAL;
  }
#else
  // on windows, assume global binding for macho symbols
  info.symbol_binding = symbol_info::GLOBAL;
#endif

#ifndef _WIN32
  info.is_exported = (sym.raw_type() & N_EXT) != 0;
#else
  info.is_exported = true; // assume exported on windows
#endif
  info.is_imported = sym.type() == LIEF::MachO::Symbol::TYPE::UNDEFINED;

  return info;
}

#else // !WITNESS_LIEF_ENABLED

// stub implementations when LIEF is disabled
lief_symbol_backend::lief_symbol_backend(const config&) : log_("w1.lief_symbol_backend") {
  log_.warn("lief symbol backend created but LIEF is disabled");
}

lief_symbol_backend::~lief_symbol_backend() = default;

bool lief_symbol_backend::is_available() const { return false; }

lief_symbol_backend::capabilities lief_symbol_backend::get_capabilities() const { return {false, false, false, false}; }

void lief_symbol_backend::set_path_resolver(std::shared_ptr<path_resolver>) {}
std::optional<symbol_info> lief_symbol_backend::resolve_address(uint64_t) const { return std::nullopt; }
std::optional<uint64_t> lief_symbol_backend::resolve_name(const std::string&, const std::string&) const {
  return std::nullopt;
}
std::optional<symbol_info> lief_symbol_backend::resolve_in_module(const std::string&, uint64_t) const {
  return std::nullopt;
}
std::vector<symbol_info> lief_symbol_backend::find_symbols(const std::string&, const std::string&) const { return {}; }
std::vector<symbol_info> lief_symbol_backend::get_module_symbols(const std::string&) const { return {}; }
void lief_symbol_backend::clear_cache() {}

lief_binary_cache::lief_binary_cache(size_t)
    : max_size_(0), hits_(0), misses_(0), negative_hits_(0), log_("w1.lief_binary_cache") {}
lief_binary_cache::~lief_binary_cache() = default;
void lief_binary_cache::clear() {}
lief_binary_cache::cache_stats lief_binary_cache::get_stats() const { return {0, 0, 0, 0.0}; }

#endif // WITNESS_LIEF_ENABLED

} // namespace w1::symbols