#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <cstdint>

namespace p1ll::core {

// platform abstraction
struct platform_key {
  std::string os;   // "windows", "linux", "darwin"
  std::string arch; // "x64", "arm64", "*" (wildcard)

  std::string to_string() const { return os + ":" + arch; }
  bool matches(const platform_key& other) const;
  bool operator==(const platform_key& other) const { return os == other.os && arch == other.arch; }
};

// signature types
using signature_pattern = std::string; // "ff d0 ?? 74"
using patch_pattern = std::string;     // "90 90 eb"

// compiled signature with mask for wildcards
struct compiled_signature {
  std::vector<uint8_t> pattern; // exact bytes
  std::vector<bool> mask;       // true = exact, false = wildcard
  size_t size() const { return pattern.size(); }
  bool empty() const { return pattern.empty(); }
};

// compiled patch data
struct compiled_patch {
  std::vector<uint8_t> data; // bytes to write
  std::vector<bool> mask;    // true = write byte, false = skip
  size_t size() const { return data.size(); }
  bool empty() const { return data.empty(); }
};

// signature query filtering configuration
struct signature_query_filter {
  std::string pattern; // regex pattern for region name filtering

  // helper to check if filter is empty (matches all)
  bool is_empty() const { return pattern.empty(); }
};

// signature query with filtering
struct signature_query {
  compiled_signature signature;
  signature_query_filter filter;
};

// signature object (for referencing in patches)
struct signature_object {
  signature_pattern pattern;
  std::optional<signature_query_filter> filter;
  bool single = false; // enforce exactly one match

  signature_object() = default;
  signature_object(const signature_pattern& p) : pattern(p) {}
  signature_object(const signature_pattern& p, const signature_query_filter& f) : pattern(p), filter(f) {}
  signature_object(const signature_pattern& p, const signature_query_filter& f, bool s)
      : pattern(p), filter(f), single(s) {}

  std::string to_string() const { return pattern; }
};

// patch declaration - references signature object
struct patch_declaration {
  signature_object signature; // signature object reference
  uint64_t offset;            // offset from signature match
  patch_pattern pattern;      // hex bytes to write
  bool required = true;       // fail if patch cannot be applied

  std::string to_string() const;
};

// auto-cure metadata
struct cure_metadata {
  std::string name;
  std::vector<std::string> platforms;
};

// platform signature mapping: "os:arch" -> [signature_objects]
using platform_signature_map = std::unordered_map<std::string, std::vector<signature_object>>;

// platform patch mapping: "os:arch" -> [patches]
using platform_patch_map = std::unordered_map<std::string, std::vector<patch_declaration>>;

// complete auto-cure configuration
struct cure_config {
  cure_metadata meta;
  platform_signature_map signatures;
  platform_patch_map patches;
};

// memory search result
struct search_result {
  uint64_t address;
  std::string region_name;
  std::string section_name;

  search_result() : address(0) {}
  search_result(uint64_t addr, const std::string& region = "", const std::string& sec = "")
      : address(addr), region_name(region), section_name(sec) {}
};

// module information
struct module_info {
  std::string name;
  std::string path;
  uint64_t base_address;
  uint64_t size;
  std::string permissions;
  bool is_system_module;

  module_info() : base_address(0), size(0), is_system_module(false) {}
};

// auto-cure execution result
struct cure_result {
  bool success = false;
  size_t patches_applied = 0;
  size_t patches_failed = 0;
  std::vector<std::string> error_messages;

  void add_error(const std::string& error) { error_messages.push_back(error); }

  bool has_errors() const { return !error_messages.empty(); }
};

} // namespace p1ll::core