#pragma once

#include "core/types.hpp"
#include "memory_types.hpp"
#include "pattern_matcher.hpp"
#include <vector>
#include <string>
#include <memory>
#include <optional>
#include <variant>
#include <redlog.hpp>

namespace p1ll::engine {

// Error type definitions removed - using std::optional<T> and bool returns with logging

class memory_scanner {
public:
  memory_scanner();
  ~memory_scanner() = default;

  // --- High-Level Signature Scanning ---
  /**
   * @brief Searches for a signature across all committed memory regions, respecting the filter.
   * @param query The signature and a filter to select which regions to search.
   * @return A list of all found matches.
   */
  std::optional<std::vector<search_result>> search(const signature_query& query) const;

  // --- Low-Level Memory Introspection & Manipulation ---
  // enumerates memory regions in current process, optionally filtered
  std::optional<std::vector<memory_region>> get_memory_regions(const signature_query_filter& filter = {}) const;

  // gets memory region info for a specific address
  std::optional<memory_region> get_region_info(uint64_t address) const;

  // changes memory protection with w^x compliance (removes execute when enabling write)
  bool set_memory_protection(uint64_t address, size_t size, memory_protection protection) const;

  // gets system page size in bytes
  std::optional<size_t> get_page_size() const;

  // --- Memory Allocation ---
  // allocates memory with specified protection (size must be page-aligned)
  std::optional<void*> allocate_memory(size_t size, memory_protection protection) const;

  // frees memory allocated by allocate_memory()
  bool free_memory(void* address, size_t size) const;

  // --- Direct Memory Access ---
  // reads memory from current process (validates range is in single readable region)
  std::optional<std::vector<uint8_t>> read_memory(uint64_t address, size_t size) const;

  // writes data to memory in current process (validates range is in single writable region)
  bool write_memory(uint64_t address, const std::vector<uint8_t>& data) const;

  // --- Cache Management ---
  // flushes instruction cache to ensure cpu sees modified code
  bool flush_instruction_cache(uint64_t address, size_t size) const;

private:
  mutable redlog::logger log_;

  // Platform-agnostic private helpers
  bool is_system_region(const memory_region& region) const;
  bool matches_filter(const memory_region& region, const signature_query_filter& filter) const;

  // Platform-specific implementations
  std::optional<std::vector<memory_region>> enumerate_regions() const;
#ifdef __APPLE__
  std::optional<std::vector<memory_region>> enumerate_regions_macos() const;
#endif
#ifdef __linux__
  std::optional<std::vector<memory_region>> enumerate_regions_linux() const;
#endif
#ifdef _WIN32
  std::optional<std::vector<memory_region>> enumerate_regions_windows() const;
#endif
  std::optional<std::vector<memory_region>> log_and_return_regions(const std::vector<memory_region>& regions) const;

  // Protection flag conversion helpers
  std::optional<memory_protection> platform_to_protection(int platform_protection) const;
  std::optional<int> protection_to_platform(memory_protection protection) const;
};

} // namespace p1ll::engine
