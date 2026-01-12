#pragma once

#include "result.hpp"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace p1ll::engine {

// memory protection flags used across the engine
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
  uint64_t base_address = 0;
  size_t size = 0;
  memory_protection protection = memory_protection::none;
  std::string name;
  bool is_executable = false;
  bool is_system = false;
};

struct scan_filter {
  std::string name_regex;
  bool only_executable = false;
  bool exclude_system = false;
  size_t min_size = 0;
  std::optional<uint64_t> min_address;
  std::optional<uint64_t> max_address;
};

struct scan_options {
  scan_filter filter;
  bool single = false;
  size_t max_matches = 0;
};

struct scan_result {
  uint64_t address = 0;
  std::string region_name;
};

struct signature_spec {
  std::string pattern;
  scan_options options;
  std::vector<std::string> platforms;
  bool required = true;
};

struct patch_spec {
  signature_spec signature;
  int64_t offset = 0;
  std::string patch;
  std::vector<std::string> platforms;
  bool required = true;
};

struct recipe {
  std::string name;
  std::vector<std::string> platforms;
  std::vector<signature_spec> validations;
  std::vector<patch_spec> patches;
};

struct plan_entry {
  patch_spec spec;
  uint64_t address = 0;
  std::vector<uint8_t> patch_bytes;
  std::vector<uint8_t> patch_mask;
};

struct apply_report {
  bool success = false;
  size_t applied = 0;
  size_t failed = 0;
  std::vector<status> diagnostics;
};

} // namespace p1ll::engine
