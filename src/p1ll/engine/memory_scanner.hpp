#pragma once

#include "core/types.hpp"
#include "pattern_matcher.hpp"
#include <vector>
#include <string>
#include <memory>
#include <optional>
#include <variant>
#include <redlog.hpp>

namespace p1ll::engine {

enum class memory_protection : int {
  none = 0x00,
  read = 0x01,
  write = 0x02,
  execute = 0x04,
  read_write = read | write,
  read_execute = read | execute,
  read_write_execute = read | write | execute
};
constexpr memory_protection operator|(memory_protection a, memory_protection b) {
  return static_cast<memory_protection>(static_cast<int>(a) | static_cast<int>(b));
}
constexpr memory_protection operator&(memory_protection a, memory_protection b) {
  return static_cast<memory_protection>(static_cast<int>(a) & static_cast<int>(b));
}
constexpr bool has_protection(memory_protection flags, memory_protection check) { return (flags & check) == check; }

struct memory_region {
  uint64_t base_address;
  size_t size;
  memory_protection protection;
  std::string name;
  bool is_executable; // Flag for regions that are part of a module's code
  bool is_system;     // Flag for regions belonging to system libraries
};

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

private:
  mutable redlog::logger log_;

  // Platform-agnostic private helpers
  bool is_system_region(const memory_region& region) const;
  bool matches_filter(const memory_region& region, const signature_query_filter& filter) const;

  // Platform-specific implementations
  std::optional<std::vector<memory_region>> enumerate_regions() const;

  // Protection flag conversion helpers
  std::optional<memory_protection> platform_to_protection(int platform_protection) const;
  std::optional<int> protection_to_platform(memory_protection protection) const;
};

} // namespace p1ll::engine